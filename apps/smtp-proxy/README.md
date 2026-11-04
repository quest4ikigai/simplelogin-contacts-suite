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
sending the same message twice: by default
(`SMTP_PROXY_DUPLICATE_SUPPRESSION_WINDOW_SECONDS=86400`), the proxy
fingerprints every message it is about to forward (its `Message-Id`, or a
content hash if that header is absent, plus its envelope sender and
rewritten recipients) and atomically reserves that fingerprint in the local
SQLite cache *before* forwarding starts, releasing the reservation again if
forwarding fails. Reserving up front (rather than only recording success
afterward) closes the race where a client disconnects mid-send and
immediately retries: both submissions would otherwise be able to pass a
simple "was this forwarded already?" check before either one finishes, and
both would be sent. A resubmission that matches a fingerprint already
reserved or forwarded within the window is rejected with `550 Duplicate
submission suppressed` instead of being sent again. Set the window to `0`
to disable this check entirely.

This is a best-effort safeguard, not a delivery guarantee: a mail client that
assigns a new `Message-Id` on every retry (rather than resending the exact
same compose) will not be caught by it, and the proxy cannot make SMTP itself
exactly-once. Treat the dedup window as reducing the odds of an accidental
duplicate send after an ambiguous client disconnect, not eliminating them.

## Diagnostics and logging

Each SMTP submission gets a short `correlation_id` that appears on every
audit event logged for it (`smtp_transform_plan`, `smtp_message_forwarded`,
`smtp_message_rejected`, `smtp_client_disconnected_during_processing`, etc.),
so one submission's full lifecycle can be followed across both the event
loop and worker-thread log lines. The `smtp_transform_plan` event also
reports timing (`alias_refresh_ms`, `resolution_ms`,
`transform_validate_ms`) and SimpleLogin API/cache efficiency
(`simplelogin_request_count`, `simplelogin_request_duration_ms`,
`cache_hit_count`, `cache_miss_count`, `contacts_found`, `contacts_created`)
for that submission.

`aiosmtpd` itself logs raw, unredacted SMTP protocol lines (including literal
`MAIL FROM`/`RCPT TO` addresses) under the `mail.log` logger name. The proxy
defaults that logger to `WARNING` regardless of `LOG_LEVEL`, so normal
operation never leaks addresses through it. Set
`SMTP_PROXY_AIOSMTPD_LOG_LEVEL=INFO` (or `DEBUG`) only for temporary protocol
troubleshooting, with the explicit understanding that doing so exposes real
recipient addresses in the logs.
