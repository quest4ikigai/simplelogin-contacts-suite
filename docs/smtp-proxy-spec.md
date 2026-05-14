# SMTP Proxy Spec

The implementation accepts SMTP submission, parses the envelope and MIME
recipients, builds a transform plan, logs a redacted summary, and dry-run rejects
by default. When `SMTP_PROXY_DRY_RUN=false`, it rewrites safe recipients and
headers before forwarding to upstream SMTP.

Forwarding must:

- Rewrite envelope recipients to SimpleLogin reverse aliases.
- Rewrite visible `To` and `Cc` headers when configured.
- Preserve Bcc privacy.
- Strip self aliases and own mailboxes.
- Preserve existing SimpleLogin reverse aliases.
- Select exactly one SimpleLogin alias from `X-SimpleLogin-Alias` or any `To`, `Cc`, or `Bcc` recipient.
- Reject messages that specify two distinct SimpleLogin aliases.
- Strip internal metadata headers and alias selector recipients.
- Support a single `To` alias cover recipient for anonymized Bcc sends by preserving the visible `To` header while dropping that alias from the SMTP envelope.
