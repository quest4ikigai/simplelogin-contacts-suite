# Architecture

The suite is SMTP-proxy-first.

```text
Apple Mail SMTP -> apps/smtp-proxy -> Proton Bridge SMTP -> Proton Mail
Apple Mail IMAP -> Proton Bridge IMAP
apps/smtp-proxy -> SimpleLogin API
```

Shared logic lives in `packages/`. The contacts sync app in
`apps/server-sync/` is now optional convenience, not part of the core send path.

The original detailed plan lives in `docs/plans/01-ARCHITECTURE.md`.
