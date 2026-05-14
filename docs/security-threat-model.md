# Security Threat Model

The SMTP proxy is a trusted outbound submission proxy. It can see plaintext
outbound mail before Proton Bridge receives it, so its defaults are intentionally
conservative:

- Require SMTP auth by default.
- Prefer localhost or VPN-only exposure.
- Fail closed when SimpleLogin routing cannot be completed.
- Never log message bodies, attachments, subjects, API keys, or SMTP passwords
  by default.
- Strip `X-SimpleLogin-*` internal metadata headers before any future forwarding.
