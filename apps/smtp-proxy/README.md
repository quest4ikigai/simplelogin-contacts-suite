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
