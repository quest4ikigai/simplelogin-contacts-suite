# Security Threat Model

The SMTP proxy is a trusted outbound submission proxy. It can see plaintext
outbound mail before Proton Bridge receives it, so its defaults are intentionally
conservative:

- Require SMTP auth by default.
- Delay failed SMTP auth attempts to slow credential guessing.
- Prefer localhost or VPN-only exposure.
- Fail closed when SimpleLogin routing cannot be completed.
- Never log message bodies, attachments, subjects, API keys, or SMTP passwords
  by default.
- Emit structured audit events with policy outcomes and counts only.
- Strip `X-SimpleLogin-*` internal metadata headers before any future forwarding.
