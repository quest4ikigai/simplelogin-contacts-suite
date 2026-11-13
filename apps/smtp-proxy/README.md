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
contact list fetch per recipient. This prefetch is skipped entirely when
`ALLOW_DIRECT_EXTERNAL_SEND=true`: in that mode the planner keeps external
recipients unchanged and never calls the reverse-alias resolver for them,
so prefetching would only cost extra SimpleLogin API calls and create
reverse-alias contacts that nothing ever uses.

Relevant settings:

```dotenv
SMTP_PROXY_RESOLVER_MAX_WORKERS=4
SMTP_PROXY_FORWARD_MAX_WORKERS=4
SMTP_PROXY_MAX_CONCURRENT_SUBMISSIONS=20
```

`SMTP_PROXY_RESOLVER_MAX_WORKERS` bounds how many messages can have their
recipient resolution in flight against the SimpleLogin API at once.
`SMTP_PROXY_FORWARD_MAX_WORKERS` bounds concurrent upstream SMTP forwarding.
Both default to 4 and exist to cap thread/connection growth under concurrent
load rather than to tune for a specific throughput target.

`SMTP_PROXY_MAX_CONCURRENT_SUBMISSIONS` is a separate, broader limit: how
many submissions can be inside message processing at all (parsed,
resolving, transforming, or forwarding) at once, regardless of which
worker pool they currently need. The two worker-pool settings above only
bound how many threads are *actively* running -- `run_in_executor`'s own
queue is unbounded, so without this separate admission limit, a client
opening enough concurrent sessions and submitting messages up to
`SMTP_PROXY_MAX_MESSAGE_BYTES` each while the worker pools are busy (for
example with many uncached recipients) could have unboundedly many
submissions each holding their own parsed/transformed copy of their
message in memory while waiting for a free worker -- unbounded memory
growth with a correspondingly reachable path to exhausting the process.
A submission beyond this limit is rejected immediately with a temporary
`451`, before any parsing or resolution work, rather than being accepted
and left queued; a well-behaved client retries it once capacity frees up.
Raise it if legitimate concurrent load routinely hits the default of 20;
lower it (or lower `SMTP_PROXY_MAX_MESSAGE_BYTES`) to trade throughput for
a smaller worst-case memory ceiling.

The duplicate-suppression cache (below) gets its own small, fixed-size
worker pool for the same reason resolution and forwarding do: SQLite can
block a caller behind its own busy-timeout if the database file is
locked by a concurrent writer (another connection's write, or a schema
migration), and that wait must never happen directly on the event loop,
or it would stall every other connection and health probe for as long
as the lock is held.

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
fingerprints every message it is about to forward (its envelope sender,
rewritten recipients, `Message-Id` if present, and *always* a hash of the
full serialized message) and atomically reserves that fingerprint in the
local SQLite cache *before* forwarding starts. The content hash is
included even when `Message-Id` is present -- not only as a fallback --
so a client-side "edit and resend" that reuses the same `Message-Id`, or
two separately imported messages that happen to share one, are never
fingerprinted as the same message just because the sender, recipients,
and `Message-Id` all match; only a byte-identical resubmission is ever
suppressed. Reserving up front (rather than only recording success
afterward) closes the race where a client disconnects mid-send and
immediately retries: both submissions would otherwise be able to pass a
simple "was this forwarded already?" check before either one finishes,
and both would be sent.

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
- **Forwarding partially accepted.** The upstream server confirmed-accepted
  *some* recipients and confirmed-refused the rest of the same matching
  message (see "Partial recipient acceptance" below). Unlike every other
  state, this is never reclaimed by age at all -- not after the
  suppression window, and not by the background pruning that otherwise
  bounds the table's size. The proxy has no way to resend to only the
  refused subset, so the recipients already accepted must never receive
  a second copy, and a standard SMTP client (or an intermediate MTA) is
  entitled to keep retrying a temporary failure indefinitely, so no
  elapsed time would ever make reforwarding safe. A resubmission is
  rejected permanently with `550` and an `smtp_duplicate_partial_delivery`
  audit event, not reported as outright success or deferred for a later
  retry.
- **Forwarding confirmed failed.** A matching attempt raised a confirmed
  `UpstreamForwardingError` -- one known to have occurred *before* any
  message data was sent (connection refused, EHLO/STARTTLS/AUTH failure)
  or in response to the upstream's own definitive rejection reply
  (`SMTPRecipientsRefused`, `SMTPSenderRefused`, `SMTPDataError`). Nothing
  was delivered, so the fingerprint is immediately reclaimable: a
  resubmission is forwarded again like a fresh message. A connection lost
  or timed out *while* the message was already being transmitted is
  deliberately **not** treated as confirmed -- see "ambiguous" below.
  Note that `forward()` manages its upstream connection manually rather
  than via `smtplib.SMTP`'s own context manager: that context manager's
  `__exit__` sends `QUIT` and raises on a non-221 reply, which, since
  `sendmail()` had already returned successfully by that point, would
  otherwise turn a *confirmed delivery* into a reported failure and let
  an immediate retry resend an already-accepted message. A `QUIT`/close
  failure is always swallowed as best-effort session teardown; it never
  overrides the outcome `sendmail()` itself already established.
- **Pending reservation abandoned (process killed mid-send).** The
  reservation's lease expired without being resolved into "completed" or
  "failed" -- most likely because the proxy process was killed or crashed
  while forwarding was in progress. The proxy cannot assume the original
  send never reached the upstream server, so it does not forward on its
  behalf and does not treat it as a confirmed failure either: it defers
  with `451` (audited as `duplicate_reservation_abandoned`) until the
  abandoned-reservation grace period also elapses.
- **Delivery outcome unknown (ambiguous upstream failure, or an unexpected
  error, while the process is still alive).** Two distinct situations
  land here, both genuinely ambiguous: (1) an `UpstreamForwardingError`
  whose underlying cause was a lost or timed-out connection *while*
  `sendmail()` was transmitting the envelope or DATA, or waiting for its
  final reply -- the upstream may have already received and accepted the
  message bytes before this happened; and (2) any exception other than
  `UpstreamForwardingError` escaping forwarding entirely (a bug, not a
  normal upstream failure). In both cases the proxy cannot tell whether
  the message reached the upstream server, so it leaves the reservation
  pending rather than guessing; it is then handled by the *same*
  pending/abandoned logic above as time passes. See "Diagnostics and
  logging" below for how this is still audited.

### Partial recipient acceptance

`smtplib.SMTP.sendmail()` raises `SMTPRecipientsRefused` only when *every*
recipient is refused. Whenever at least one recipient is accepted, it
instead returns normally with a dict of whichever recipients *were*
refused (empty if none were) -- and the message has already been fully
transmitted and accepted for the rest by that point. The proxy inspects
that return value rather than treating "no exception" as "everyone got
it": a message to several recipients where the upstream server accepts
most of them and refuses one (a typo'd address, a full mailbox, a
recipient-level policy rejection) is recorded as **partially accepted**,
distinct from both a complete success and a complete failure.

SMTP has no way to give a *per-recipient* reply at this stage -- the
proxy already replied `250 OK` to every `RCPT TO` when the client
submitted the message, before it knew the full MIME content or had
contacted the upstream server, so the only thing left to answer is the
single reply to `DATA`. A plain `250` here would misreport the refused
recipient as having received the message. A *temporary* (`4xx`) response
was considered instead of a permanent one, specifically to avoid implying
the entire submission failed when most of it was delivered -- but a `4xx`
response is not just a politer word choice: it is an explicit, standard
invitation for a compliant SMTP client or an intermediate relaying MTA to
automatically retry the identical message later, with no action from the
original sender at all. If duplicate suppression is disabled
(`SMTP_PROXY_DUPLICATE_SUPPRESSION_WINDOW_SECONDS=0`) that retry would be
forwarded again immediately; even with it enabled, a `4xx` paired with a
reservation that eventually expired would just delay, not prevent, an
automatic resend reaching the recipients who already got the message. So
the proxy reports a *permanent* failure instead -- `550`, whose text
states the actual split (`"550 Message delivered to N of M recipient(s);
R recipient(s) were refused by the upstream mail server..."`) so a human
reading the response still understands most of the message went through
-- and logs an `smtp_message_partially_forwarded` audit event with
`accepted_count`, `refused_count`, the total `recipient_count`, and the
upstream's numeric `refused_smtp_codes`. The dedup reservation is marked
`partial` and, uniquely among every outcome this proxy tracks, is *never*
reclaimed automatically regardless of how much time passes (see above):
even a blind resend of the identical message, today or a year from now,
gets the same permanent `550` and is never forwarded again.

Recovering from a partial acceptance is necessarily a manual step: the
proxy has no mechanism to resend to only the refused recipient (SMTP
submission here is all-or-nothing per message), and it does not attempt
automatic recipient-level retries. Recipient addresses are deliberately
never written to the normal audit log or the `550` response -- for
addresses rewritten to a SimpleLogin reverse alias, the original sender
could not identify the affected recipient from the raw refused address
anyway, since that mapping is internal to the proxy and SimpleLogin.

To identify which recipient was refused, read the `detail` column of
that fingerprint's row in the SQLite cache directly:

```bash
sqlite3 /data/cache.sqlite3 \
  "SELECT fingerprint, detail FROM forwarded_messages WHERE status = 'partial'"
```

`detail` is a small JSON object (`refused_recipients`, `refused_smtp_codes`)
recorded on the row at the moment of the partial acceptance, and is never
written to any log stream -- an operator reads it the same way they would
already read the `contacts` table's plaintext email addresses, the same
local trust boundary. This is the durable recovery path, not a
`LOG_LEVEL=DEBUG` log line: because the fingerprint can never be
reforwarded (see above), the exact submission can never be replayed
later to reproduce the missing detail if it was only ever logged at a
level nobody happened to be watching at the time. (`forwarder.py` still
emits the same detail at `DEBUG`, off by default, purely as a live-
tailing convenience -- not as the thing to rely on after the fact. That
`DEBUG` line also honors `LOG_REDACT_ADDRESSES` exactly like every other
address this app logs: with the default `LOG_REDACT_ADDRESSES=true`,
addresses in it are partially masked and the upstream's raw response
text is omitted entirely, the same as the `detail` column above;
disabling address redaction is what shows the fully unmasked dict
there, same as it does everywhere else in this app's logs.)
With the refused recipient identified, the operator (or the original
sender, for recipients they typed themselves and who were not rewritten
to a reverse alias) can send a new, standalone message to just that
recipient -- a fresh compose gets its own fingerprint and is unaffected
by the permanent block on the original one.

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

The `forwarded_messages` SQLite table gained `status` (`pending`,
`completed`, `partial`, or `failed`), `attempt_id`, and `detail` columns
in this change. All are added with an additive, idempotent migration run
on every connection, so an existing persistent `/data/cache.sqlite3`
volume from an earlier
version of this feature upgrades in place with no manual steps. `detail`
is populated only for `partial` rows (see "Partial recipient acceptance"
above); it is `NULL` for every other status. Rows with
status `partial` are never swept up by the opportunistic pruning that
otherwise bounds this table's size (see above) -- they are expected to be
rare, and an operator who resolves one by hand can delete its row
manually if it needs to be reclaimed.

## Graceful shutdown

`docker stop`, `docker compose down`, and a rolling container replacement
all send SIGTERM to the proxy's main process. The proxy catches both
SIGTERM and SIGINT and runs an orderly shutdown rather than relying on
the process simply being killed -- without this, an in-flight forward
already accepted by the upstream server could be cut off mid-send with
no chance to record its outcome, recreating the original incident's
silent-success problem at shutdown time instead of client-disconnect
time. A second signal (an impatient double Ctrl-C, or a monitoring tool
re-sending SIGTERM) never triggers a second, concurrent shutdown -- the
signal handler just idempotently marks that shutdown was requested, and
nothing re-starts it once under way. The handlers stay installed for
the *entire* drain-then-stop sequence below, not just until the first
signal arrives: removing them any earlier would mean that second signal
falls through to the process's default disposition instead (SIGTERM
killing the process immediately, SIGINT raising `KeyboardInterrupt` out
of `asyncio.run`), defeating graceful shutdown for exactly the in-flight
forward it exists to protect. Only Docker's own SIGKILL, sent once
`stop_grace_period` elapses, can still end the process outright --
signals cannot be caught at all once that happens.

Shutdown proceeds in three strict steps, in this order:

1. **Stop accepting new forwarding work.** Every in-progress and future
   `handle_DATA` call -- a brand-new connection that raced in after
   shutdown began, or an already-established session (past
   `EHLO`/`MAIL`/`RCPT`) sending a second message -- is checked right
   before it would create a forwarding task, however far along it
   already is in recipient resolution. Once shutdown has begun, it gets
   a permanent `451` (`"...is shutting down; please retry this message
   later"`) instead, so a well-behaved client knows to retry once the
   proxy (or its replacement container) is back. This has to happen
   *before* the next step, not after: a new submission reaching the
   forwarding stage in the gap between starting to drain and actually
   stopping the SMTP controller would create a task the drain never
   knew to wait for, which `Controller.stop()` would then cancel
   without ever recording its outcome -- simply closing the listening
   socket is not enough on its own, since an already-established
   session could still submit a second message on the same connection.
2. **Drain in-flight forwards.** Every submission that already created
   its shielded reservation-claim-and-forward task before step 1 took
   effect is waited on, same as calling `stop()` directly (see "Delivery-state
   handling" above) -- up to `UPSTREAM_SMTP_TIMEOUT_SECONDS + 5` seconds
   (35s at the documented default).
3. **Tear down.** The worker thread pools and the SMTP controller
   (and its dedicated event-loop thread) are shut down.

If the drain deadline in step 2 is reached with forwards still
outstanding, the proxy does not wait any longer: it logs a warning
naming how many, and proceeds to step 3 anyway. Each such forward's
dedup reservation is left exactly as it was written when claimed --
`pending` -- because the cancelled task never reaches
`mark_forwarded`/`mark_failed`/`mark_partial` to record a real outcome,
and the proxy will not claim a delivery outcome it cannot actually
confirm. This is the same documented state, and the same recovery path,
as a process crash mid-send (see "Leases, renewal, and recovering from a
crash" above): a resubmission after restart sees it as in-flight, then
abandoned once the lease expires, and is only reclaimed (accepting the
same small residual duplicate-delivery risk already documented for that
path) after the abandoned-reservation grace period. In practice this
should be rare -- the deadline is already sized to the upstream
connection's own timeout -- but it is not eliminated, which is why
`deploy/docker/docker-compose.smtp-proxy.yml` sets
`stop_grace_period: 45s`, comfortably above that 35s default so Docker's
own SIGKILL does not arrive before the proxy's orderly drain would have
finished on its own. If `UPSTREAM_SMTP_TIMEOUT_SECONDS` is raised,
increase `stop_grace_period` by the same amount.

On a platform where `asyncio`'s signal handling isn't available (POSIX
only, and only from the main thread of the main interpreter), the proxy
falls back to blocking indefinitely instead, exactly as it did before
this feature existed -- an operator in that environment still relies on
the process being terminated outright.

## Diagnostics and logging

Each SMTP submission gets a short `correlation_id` that appears on every
audit event logged for it, so one submission's full lifecycle can be
followed across both the event loop and worker-thread log lines, even
across a client disconnect. Every forwarding attempt reaches exactly one
of these terminal audit events -- none of them is ever silently skipped:

- `smtp_message_forwarded`: forwarded and accepted upstream.
- `smtp_message_partially_forwarded`: the upstream server
  confirmed-accepted some recipients and confirmed-refused the rest; see
  "Partial recipient acceptance" above. Carries `accepted_count`,
  `refused_count`, the total `recipient_count`, and `refused_smtp_codes`
  -- never the refused addresses themselves.
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
- `smtp_duplicate_partial_delivery`: a matching submission already
  partially delivered; permanently rejected with `550` without
  forwarding again, rather than being reported as either success or a
  retryable failure.
- `smtp_client_disconnected_during_processing`: the submitting client
  disconnected before a response could be sent, carrying the same
  `correlation_id` as whichever of the above events eventually resolves
  that submission's forwarding attempt.
- `smtp_message_rejected` (`policy=server_shutting_down`): a submission
  arrived (or was already in progress) after graceful shutdown began;
  see "Graceful shutdown" below.
- `smtp_message_rejected` (`policy=at_capacity`): `SMTP_PROXY_MAX_CONCURRENT_SUBMISSIONS`
  was already reached; carries `in_flight_submissions` (a count, never
  addresses). See "Bulk recipients and concurrency" above.

Shutdown itself logs `smtp_proxy_shutdown_signal_received`
(`signal=SIGTERM`/`SIGINT`), `smtp_proxy_shutdown_started`, and
`smtp_proxy_shutdown_completed` -- see "Graceful shutdown" below for the
sequence these bracket.

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
