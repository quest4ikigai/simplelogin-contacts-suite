# SimpleLogin Alias Suite

This repo is evolving from a SimpleLogin-to-Nextcloud contacts sync MVP into a
small suite for using SimpleLogin aliases safely from Apple Mail.

The central feature is an outbound SMTP submission proxy:

```text
Apple Mail SMTP -> SimpleLogin SMTP Proxy -> Proton Bridge SMTP -> Proton Mail
Apple Mail IMAP -> Proton Bridge IMAP
```

Apple Mail can keep reading mail directly through Proton Bridge IMAP. Outbound
mail goes through the proxy, where recipients can be checked, self-aliases can
be stripped from reply-all, external recipients can be routed through
SimpleLogin reverse aliases, and unsafe sends can fail closed instead of
leaking real recipient addresses.

## Repository Layout

```text
apps/
  smtp-proxy/      Local SMTP submission proxy scaffold.
  server-sync/     Existing Nextcloud Contacts sync MVP.
  macos-helper/    Future MailKit/helper design notes.
packages/
  alias-routing-core/   Pure recipient classification and transform planning.
  simplelogin-client/   SimpleLogin API wrapper.
  contacts-core/        Shared generated-contact naming helpers.
  shared-models/        Shared config and email-address helpers.
deploy/docker/          Docker deployment files for the apps.
docs/plans/             Original implementation plan pack.
```

## Current Status

The contacts sync app remains usable from `apps/server-sync`. The SMTP proxy is
implemented as a fail-closed local service: it accepts SMTP submissions, parses
the envelope and message recipients, resolves SimpleLogin reverse aliases,
rewrites recipients and safe headers, and forwards to upstream SMTP only when
`SMTP_PROXY_DRY_RUN=false`.

## Run The Existing Contacts Sync

Use the server-sync deployment file from `deploy/docker`:

```bash
cd deploy/docker
cp .env.server-sync.example .env
docker compose -f docker-compose.server-sync.yml up -d --build
docker logs -f simplelogin-nextcloud-contacts
```

Keep `DRY_RUN=true` for the first run. Detailed setup and troubleshooting for
the sync app live in `apps/server-sync/README.md`.

## Run The SMTP Proxy Scaffold Locally

```bash
cd apps/smtp-proxy
python -m pip install -e ../../packages/alias-routing-core -e ../../packages/simplelogin-client -e .
python -m sl_smtp_proxy.main
```

The proxy reads configuration from environment variables. See
`deploy/docker/.env.smtp-proxy.example` for proxy-only deployment defaults. By
default it fails closed, redacts logs, and dry-run rejects instead of
forwarding messages.

## Safety Defaults

- SMTP auth is enabled by default.
- The proxy fails closed by default.
- Direct external sends are not allowed.
- `X-SimpleLogin-*` internal metadata headers are stripped before forwarding.
- Logs redact addresses and never include bodies, attachments, subjects, API
  keys, or SMTP passwords by default.

## Roadmap

1. Preserve the existing contacts sync app in the new layout.
2. Build deterministic alias-routing logic and tests.
3. Wrap the SimpleLogin API with redacted errors.
4. Scaffold the fail-closed SMTP proxy.
5. Add broader rewrite and forwarding coverage for Proton Bridge SMTP.
6. Add Docker deployment examples and hardening.
7. Design the optional macOS helper for alias selection UX.

## License

MIT
