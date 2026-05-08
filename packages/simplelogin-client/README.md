# SimpleLogin Client

Small SimpleLogin API wrapper for the alias suite.

The public client exposes the operations the SMTP proxy needs:

- `list_aliases()`
- `list_contacts(alias_id)`
- `create_contact(alias_id, contact)`
- `get_or_create_contact(alias_id, contact)`

Errors redact configured secrets before they are surfaced to callers or logs.
