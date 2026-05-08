# Alias Routing Core

Pure recipient classification and transform planning for the SimpleLogin SMTP
proxy.

This package has no network or SMTP dependencies. It classifies recipients,
selects exactly one SimpleLogin alias from the explicit header or any `To`/`Cc`/`Bcc` recipient, and builds a
transform plan with `KEEP`, `DROP`, `REWRITE`, and `REJECT` actions.
