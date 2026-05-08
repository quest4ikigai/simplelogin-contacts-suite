# macOS Helper Specification

## Purpose

The macOS helper should make alias selection pleasant when a user has hundreds
of SimpleLogin aliases. It should not be required for privacy enforcement.

## Future Components

- Menu bar app with searchable alias picker.
- Optional MailKit extension if outgoing draft metadata can be added reliably.
- Optional Apple Contacts/iCloud write path for generated reverse-alias contacts.

## Alias Selection UX

The picker should support:

- Search by alias email, label, and note.
- Recent aliases.
- Pinned aliases.
- Clear indication of the selected alias for the active draft.

## MailKit Metadata

Preferred metadata:

```text
X-SimpleLogin-Alias: shopping@example.com
X-SimpleLogin-Contact-Lists: Vendors,Shopping
```

The SMTP proxy must strip all `X-SimpleLogin-*` headers before forwarding.

## Fallbacks

If MailKit cannot reliably add outgoing headers, users can still select aliases
with:

- Exactly one alias in `To`, `Cc`, or `Bcc`, such as `Cc: orders@example.net`, when the suffix is listed in `ALIAS_SUFFIX_DOMAINS` or the alias is discovered from SimpleLogin.
- A single `To` alias cover recipient for anonymized Bcc sends, such as
  `To: announcements@example.net` plus external recipients in Bcc.

## Contacts

Generated Apple Contacts should store only the reverse-alias address as an email
field. The original recipient address belongs in notes/metadata, not an email
field, to avoid Apple Mail autocomplete leaking the real address.
