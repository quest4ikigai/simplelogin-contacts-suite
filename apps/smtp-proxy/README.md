# SimpleLogin SMTP Proxy

Fail-closed SMTP submission proxy scaffold for routing Apple Mail outbound
messages through SimpleLogin reverse aliases before forwarding to Proton Bridge
SMTP.

Current behavior:

1. Accepts local SMTP submissions.
2. Uses `aiosmtpd` for SMTP protocol handling.
3. Optionally requires SMTP AUTH PLAIN or LOGIN.
4. Parses SMTP envelope recipients and MIME `To`, `Cc`, and `Bcc` recipients.
5. Selects exactly one SimpleLogin alias from `X-SimpleLogin-Alias` or any `To`, `Cc`, or `Bcc` recipient.
6. Resolves external recipients to SimpleLogin reverse aliases using the local
   SQLite cache and SimpleLogin API.
7. Builds a redacted transform plan through `alias-routing-core`.
8. Rewrites envelope recipients and visible `To`/`Cc` headers.
9. Strips `Bcc` and all `X-SimpleLogin-*` internal metadata headers.
10. Forwards to upstream SMTP when `SMTP_PROXY_DRY_RUN=false`; otherwise rejects
    after planning so tests and local setup cannot accidentally send.

Run locally from this directory:

```bash
python -m pip install -e ../../packages/alias-routing-core -e ../../packages/simplelogin-client -e .
SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN=true python -m sl_smtp_proxy.main
```

Forwarding is disabled by default via `SMTP_PROXY_DRY_RUN=true`. Leave dry-run
enabled until fake-upstream or disposable-account tests prove your configuration
rewrites every external recipient as expected.

The local dry-run command above is an explicit development escape hatch for the
default loopback-only setup. It is rejected for `SMTP_PROXY_HOST=0.0.0.0`, `::`,
or non-loopback hostnames/IPs; remote-capable binds must use SMTP AUTH, inbound
TLS, non-default credentials, configured `USER_MAILBOXES`, and
`ALLOW_DIRECT_EXTERNAL_SEND=false`.

For upstream SMTP delivery, configure the real SMTP server and TLS mode:

```dotenv
UPSTREAM_SMTP_HOST=smtp.example.com
UPSTREAM_SMTP_PORT=587
UPSTREAM_SMTP_USERNAME=...
UPSTREAM_SMTP_PASSWORD=...
UPSTREAM_SMTP_TLS_MODE=starttls
UPSTREAM_SMTP_TLS_VERIFY=true
```

`UPSTREAM_SMTP_TLS_MODE` accepts `none`, `starttls`, or `implicit`. STARTTLS and
implicit TLS use a verifying SSL context by default. Set
`UPSTREAM_SMTP_TLS_VERIFY=false` only for a trusted upstream with a self-signed
certificate.

For remote mail clients, configure inbound proxy TLS with:

```dotenv
SMTP_PROXY_REQUIRE_TLS=true
SMTP_PROXY_TLS_MODE=starttls
SMTP_PROXY_TLS_CERT_FILE=/certs/proxy.crt
SMTP_PROXY_TLS_KEY_FILE=/certs/proxy.key
SMTP_PROXY_AUTH_LOGIN_ENABLED=true
```

`SMTP_PROXY_TLS_MODE=starttls` advertises STARTTLS after `EHLO`. If a client
starts encrypted TLS immediately on connect, use `SMTP_PROXY_TLS_MODE=implicit`
on a dedicated port instead.

For normal sends and reply-all cleanup, put exactly one alias in `To`, `Cc`, or `Bcc`; the proxy uses it as the selected sending alias and rejects if two distinct aliases appear. For anonymized Bcc sends, a single alias in `To` can also act as the visible cover recipient:

```text
To: announcements@example.net
Bcc: alice@example.org, bob@example.org
```

The proxy preserves `To: announcements@example.net`, removes that alias from the
SMTP envelope, strips `Bcc`, and forwards only the rewritten SimpleLogin reverse
aliases for the Bcc recipients.

## Bulk recipients and concurrency

Recipient resolution (SimpleLogin alias refresh and reverse-alias lookup) runs
on a bounded worker-thread pool, never on the asyncio event loop. A message
with many uncached recipients can therefore take a while to resolve without
making the proxy unresponsive to other connections or to health checks in the
meantime.

For a message with many previously-unseen recipients under the same alias,
the proxy pre-fetches that alias's SimpleLogin contact list once and resolves
every recipient against that single result (falling back automatically, per
recipient, to the original slower path if the bulk pre-fetch fails for any
reason). A 40-50 recipient classroom-style send therefore costs one contact
list fetch plus one contact-creation call per genuinely new recipient, not one
contact list fetch per recipient.

Relevant settings:

```dotenv
SMTP_PROXY_RESOLVER_MAX_WORKERS=4
SMTP_PROXY_FORWARD_MAX_WORKERS=4
```

`SMTP_PROXY_RESOLVER_MAX_WORKERS` bounds how many messages can have their
recipient resolution in flight against the SimpleLogin API at once.
`SMTP_PROXY_FORWARD_MAX_WORKERS` bounds concurrent upstream SMTP forwarding.
Both default to 4 and exist to cap thread/connection growth under concurrent
load rather than to tune for a specific throughput target.

## Delivery-state handling and duplicate submissions

Forwarding to upstream SMTP runs as its own task, shielded from cancellation.
If the submitting client disconnects (or its connection times out) while a
message is already being forwarded, the proxy does not abandon that send: the
upstream SMTP conversation runs to completion and its real outcome (forwarded
or failed) is still logged, with an `smtp_message_forwarded` or
`smtp_message_rejected` audit event carrying the same `correlation_id` as the
`smtp_client_disconnected_during_processing` event for that submission. The
original client never receives a response in this case -- SMTP cannot change
that -- but the operational logs are no longer silent about what actually
happened upstream.

This closes one, but not all, of the gaps that made a client-side retry risk
sending the same message twice. By default
(`SMTP_PROXY_DUPLICATE_SUPPRESSION_WINDOW_SECONDS=86400`), the proxy
fingerprints every message it is about to forward (its `Message-Id`, or a
content hash if that header is absent, plus its envelope sender and
rewritten recipients) and atomically reserves that fingerprint in the local
SQLite cache *before* forwarding starts. Reserving up front (rather than
only recording success afterward) closes the race where a client
disconnects mid-send and immediately retries: both submissions would
otherwise be able to pass a simple "was this forwarded already?" check
before either one finishes, and both would be sent.

### The duplicate-suppression state machine

A fingerprint is always in exactly one of these states, and the proxy's
response to a submission depends on which:

- **No prior submission.** The fingerprint is unknown. The reservation is
  claimed and the message is forwarded normally.
- **Forwarding currently pending.** Another submission with the same
  fingerprint is actively being forwarded right now (its lease -- see
  below -- has not expired). The new submission is deferred with `451`, a
  *temporary* failure: the client should retry later. It is never given a
  permanent `550` here, because the in-flight attempt might still fail, in
  which case this exact retry should go through.
- **Forwarding completed successfully.** A matching message was already
  forwarded within `SMTP_PROXY_DUPLICATE_SUPPRESSION_WINDOW_SECONDS`. The
  proxy reports `250 Message already accepted for delivery` *without*
  forwarding again, and logs an `smtp_duplicate_already_delivered` audit
  event -- the client sees success, honestly, instead of either a spurious
  error or a second delivery.
- **Forwarding confirmed failed.** A matching attempt raised a confirmed
  `UpstreamForwardingError` (e.g. the upstream rejected it, or was
  unreachable). Nothing was delivered, so the fingerprint is immediately
  reclaimable: a resubmission is forwarded again like a fresh message.
- **Pending reservation abandoned (process killed mid-send).** The
  reservation's lease expired without being resolved into "completed" or
  "failed" -- most likely because the proxy process was killed or crashed
  while forwarding was in progress. The proxy cannot assume the original
  send never reached the upstream server, so it does not forward on its
  behalf and does not treat it as a confirmed failure either: it defers
  with `451` (audited as `duplicate_reservation_abandoned`) until the
  abandoned-reservation grace period also elapses.
- **Delivery outcome unknown (unexpected error, process still alive).** An
  exception other than `UpstreamForwardingError` escaped forwarding (a bug,
  not a normal upstream failure). The proxy cannot tell whether the
  message reached the upstream server before the error, so it leaves the
  reservation pending rather than guessing; it is then handled by the
  *same* pending/abandoned logic above as time passes. See "Diagnostics
  and logging" below for how this is still audited.

### Leases, renewal, and recovering from a crash

Two settings govern the "pending" state:

```dotenv
SMTP_PROXY_DUPLICATE_RESERVATION_LEASE_SECONDS=60
SMTP_PROXY_DUPLICATE_RESERVATION_ABANDONED_GRACE_SECONDS=300
```

While a forward is genuinely in progress, the proxy renews its reservation's
lease every `lease_seconds / 3` (at least every 0.1s) for as long as the
forwarding task is alive -- so a slow-but-alive send is never mistaken for
an abandoned one just because it outlives one lease interval. Only a
process that is no longer running (crashed, killed, lost power) stops
renewing, which is what actually distinguishes "still working" from
"abandoned".

Once a reservation's lease has expired *and* it has sat unresolved for
longer than `lease_seconds + abandoned_grace_seconds` in total, the proxy
gives up waiting on it and reclaims the fingerprint for the next matching
submission, which is then forwarded for real. This is a deliberate,
documented trade-off, not a solution to exactly-once delivery: if the
original process happened to crash *after* the upstream server accepted
the message but *before* the local reservation could be marked complete,
this recovery path accepts a small residual risk of sending that message
a second time, in exchange for not blocking legitimate retries forever.
Widen the grace period if occasional stuck-looking retries are more
acceptable to you than that small residual risk; narrow it if the reverse
is true. Set `SMTP_PROXY_DUPLICATE_SUPPRESSION_WINDOW_SECONDS=0` to disable
duplicate suppression (and the reservation/lease machinery with it)
entirely.

This remains a best-effort safeguard, not a delivery guarantee: a mail
client that assigns a new `Message-Id` on every retry (rather than
resending the exact same compose) will not be caught by it, and the proxy
cannot make SMTP itself exactly-once. Treat all of the above as reducing
the odds of an accidental duplicate send or a wrongly-rejected retry, not
eliminating them.

The `forwarded_messages` SQLite table gained a `status` column (`pending`,
`completed`, or `failed`) and an `attempt_id` column in this change. Both
are added with an additive, idempotent migration run on every connection,
so an existing persistent `/data/cache.sqlite3` volume from an earlier
version of this feature upgrades in place with no manual steps.

## Diagnostics and logging

Each SMTP submission gets a short `correlation_id` that appears on every
audit event logged for it, so one submission's full lifecycle can be
followed across both the event loop and worker-thread log lines, even
across a client disconnect. Every forwarding attempt reaches exactly one
of these terminal audit events -- none of them is ever silently skipped:

- `smtp_message_forwarded`: forwarded and accepted upstream.
- `smtp_message_rejected` (`policy=upstream_unavailable`): a confirmed
  forwarding failure (`UpstreamForwardingError`).
- `smtp_forwarding_outcome_unknown` (`policy=internal_error`): an
  unexpected, non-upstream exception during forwarding. Its effect on
  upstream delivery is unknown, so it is deliberately *not* reported as a
  confirmed failure; see "Delivery-state handling" above for how the
  reservation itself is left to resolve this ambiguity over time. Carries
  a sanitized `error_type`/`error_category` (and `smtp_code` /
  `refused_recipient_count` where applicable) from
  `safe_forwarding_error_fields()` -- never the raw exception text.
- `smtp_message_deferred` (`policy=duplicate_in_flight` or
  `duplicate_reservation_abandoned`): a matching submission is already
  pending; see "Delivery-state handling" above.
- `smtp_duplicate_already_delivered`: a matching submission already
  completed; reported as success without forwarding again.
- `smtp_client_disconnected_during_processing`: the submitting client
  disconnected before a response could be sent, carrying the same
  `correlation_id` as whichever of the above events eventually resolves
  that submission's forwarding attempt.

The `smtp_transform_plan` event also reports timing (`alias_refresh_ms`,
`resolution_ms`, `transform_validate_ms`) and SimpleLogin API/cache
efficiency (`simplelogin_request_count`, `simplelogin_request_duration_ms`,
`cache_hit_count`, `cache_miss_count`, `contacts_found`, `contacts_created`)
for that submission.

`aiosmtpd` itself logs raw, unredacted SMTP protocol lines (including literal
`MAIL FROM`/`RCPT TO` addresses) under the `mail.log` logger name. The proxy
defaults that logger to `WARNING` regardless of `LOG_LEVEL`, so normal
operation never leaks addresses through it. Set
`SMTP_PROXY_AIOSMTPD_LOG_LEVEL=INFO` (or `DEBUG`) only for temporary protocol
troubleshooting, with the explicit understanding that doing so exposes real
recipient addresses in the logs.

Separately, a forwarding exception's own text is never logged either, by
either the `smtp-proxy` or `forwarder` loggers: `smtplib` exceptions such as
`SMTPRecipientsRefused` embed every refused recipient's address, and
`SMTPResponseException` (and subclasses like `SMTPDataError`) carry the
upstream server's raw response text, which can itself echo an address back
(for example `"553 mailbox name not allowed: alice@example.com"`).
Truncating that text is not a safe mitigation, since the sensitive content
can appear in the first few characters. `safe_forwarding_error_fields()` in
`forwarder.py` reduces every forwarding exception -- expected `smtplib`
failures and unexpected ones alike -- to a bounded, non-leaking summary
(exception type name, a small fixed category label, a numeric SMTP
response code when available, and a refused-recipient *count*, never the
addresses themselves) before anything is logged or audited.
