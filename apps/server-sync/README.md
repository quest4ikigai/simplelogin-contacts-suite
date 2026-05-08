# SimpleLogin Nextcloud Contacts Sync MVP

This app now lives at `apps/server-sync/` inside the broader SimpleLogin Alias
Suite. The Docker deployment file lives at
`deploy/docker/docker-compose.server-sync.yml` and runs it as
`simplelogin-nextcloud-contacts`.

This project syncs existing SimpleLogin reverse aliases into a dedicated Nextcloud Contacts address book. Once your Apple devices sync contacts from Nextcloud, Apple Mail autocomplete can suggest your SimpleLogin reverse aliases on Mac, iPhone, and iPad.

Think of it as a small address-book conveyor belt:

```text
SimpleLogin API
  -> Docker sync container
  -> Nextcloud CardDAV address book
  -> Apple Contacts / Apple Mail autocomplete
```

## What this MVP does

- Fetches your SimpleLogin aliases.
- Skips disabled SimpleLogin aliases.
- Fetches contacts/reverse aliases for each alias.
- Creates vCard contacts in a dedicated Nextcloud address book.
- Names contacts clearly, for example:

```text
SL · Alice Example · shopping@example.com
```

- Uses the SimpleLogin reverse-alias address as the contact email.
- Can delete stale generated contacts when they disappear from SimpleLogin.
- Starts in dry-run mode for safety.

## What this MVP does not do yet

- It does not create new SimpleLogin reverse aliases from Nextcloud Contacts.
- It does not provide a Nextcloud UI app.
- It does not edit your main personal address book.
- It does not integrate directly inside Apple Mail.

Phase 2 can add a small web form or Nextcloud app UI to create reverse aliases.

## Requirements

- Linux server with Docker and Docker Compose.
- Existing Nextcloud instance reachable from this container.
- Nextcloud Contacts/CardDAV enabled. This is part of Nextcloud groupware.
- A Nextcloud app password.
- A SimpleLogin API key.

## Files

```text
simplelogin-nextcloud-contacts/
  apps/server-sync/
    Dockerfile
    requirements.txt
    sync.py
  deploy/docker/
    docker-compose.server-sync.yml
    .env.server-sync.example
  README.md
```

## 1. Copy files to your server

Unzip the project on your home server:

```bash
git clone <repo-url>
cd simplelogin-nextcloud-contacts
```

## 2. Create your env file

```bash
cd deploy/docker
cp .env.server-sync.example .env
nano .env
```

Fill in at least these values:

```bash
SIMPLELOGIN_API_KEY=your_simplelogin_api_key
NEXTCLOUD_BASE_URL=https://cloud.example.com
NEXTCLOUD_USERNAME=username
NEXTCLOUD_APP_PASSWORD=your_nextcloud_app_password
```

Keep this at first:

```bash
DRY_RUN=true
```

## 3. Create a Nextcloud app password

In Nextcloud:

1. Open your user menu.
2. Go to **Personal settings**.
3. Open **Security**.
4. Under **Devices & sessions**, create a new app password.
5. Copy it into `NEXTCLOUD_APP_PASSWORD`.

Use an app password rather than your main password. Tiny safety moat, big payoff.

## 4. First dry run

Build and start the container:

```bash
docker compose -f docker-compose.server-sync.yml up -d --build
docker logs -f simplelogin-nextcloud-contacts
```

With `DRY_RUN=true`, the sync will fetch from SimpleLogin and show what it would write to Nextcloud, but it should not create or change contacts.

You should see output like:

```text
Starting simplelogin-nextcloud-contacts. Address book: SimpleLogin (simplelogin), dry_run=True
DRY_RUN: would create address book https://cloud.example.com/remote.php/dav/addressbooks/users/username/simplelogin/
DRY_RUN: would PUT sl-....vcf
Sync complete: aliases=... desired_cards=... upserts=... dry_run=True
```

## 5. Enable writes

When the dry run looks reasonable, edit `.env`:

```bash
DRY_RUN=false
```

Restart:

```bash
docker compose -f docker-compose.server-sync.yml up -d --build
docker compose -f docker-compose.server-sync.yml restart simplelogin-nextcloud-contacts
```

If your shell dislikes the line with non-English text above, just use:

```bash
docker compose -f docker-compose.server-sync.yml restart simplelogin-nextcloud-contacts
```

Watch logs:

```bash
docker logs -f simplelogin-nextcloud-contacts
```

Then open Nextcloud Contacts and look for an address book named `SimpleLogin`.

## 6. Add/sync Nextcloud contacts on Apple devices

If your Apple devices already sync contacts from this Nextcloud account, the new `SimpleLogin` address book may appear automatically.

If not, add your Nextcloud contacts account via CardDAV.

Typical values:

```text
Server: cloud.example.com
Username: your Nextcloud username
Password: your Nextcloud app password
Description: Nextcloud Contacts
```

On Apple devices, use the contacts/CardDAV account setup path for your OS version. On iOS/iPadOS this is usually under:

```text
Settings -> Apps -> Contacts -> Contacts Accounts -> Add Account -> Other -> Add CardDAV Account
```

On macOS this is usually under:

```text
System Settings -> Internet Accounts -> Add Account -> Other -> CardDAV Account
```

Exact labels vary slightly by OS release.

## 7. Use it in Apple Mail

Compose a new email and type the recipient name. Choose the contact that starts with `SL ·`.

Example:

```text
SL · Alice Example · shopping@example.com
```

Apple Mail will send to the SimpleLogin reverse-alias address. SimpleLogin then relays the message so the recipient sees the selected alias, not your real mailbox.

## Important safety notes

- Keep the generated contacts in a dedicated address book named `SimpleLogin`.
- Leave `DELETE_STALE=true` only if the address book is dedicated to this tool.
- Generated files/cards are named `sl-<hash>.vcf`.
- The script only deletes generated cards whose filenames start with `sl-`.
- The script does not write to the Nextcloud database directly. It uses CardDAV.
- Do not point this at your main personal contacts address book.
- Use HTTPS for your Nextcloud URL.
- Use a Nextcloud app password.

## Configuration reference

### SimpleLogin

```bash
SIMPLELOGIN_API_KEY=replace_me
SIMPLELOGIN_BASE_URL=https://app.simplelogin.io
```

### Nextcloud

```bash
NEXTCLOUD_BASE_URL=https://cloud.example.com
NEXTCLOUD_USERNAME=username
NEXTCLOUD_APP_PASSWORD=replace_me
NEXTCLOUD_ADDRESSBOOK_DISPLAY_NAME=SimpleLogin
NEXTCLOUD_ADDRESSBOOK_SLUG=simplelogin
```

The address book URL is built as:

```text
https://cloud.example.com/remote.php/dav/addressbooks/users/<username>/<slug>/
```

### Sync behavior

```bash
SYNC_INTERVAL_SECONDS=3600
```

How often the container runs a sync loop, in seconds. The default value `3600` means once per hour.

```bash
DRY_RUN=true
```

Preview mode.

When true, the sync should log what it would create, update, or delete, but not actually change Nextcloud Contacts.

Use this for the first run. Once the logs look right, set it to false or remove it.

```bash
DELETE_STALE=true
```

Whether to remove generated contacts from Nextcloud when they no longer exist in SimpleLogin.

For example, if a SimpleLogin reverse-alias contact was deleted or an alias stops matching your filters:

DELETE_STALE=true: delete the matching generated contact from the SimpleLogin address book.
DELETE_STALE=false: leave old generated contacts in Nextcloud.

The guardrail is that it should only delete contacts that were created by this sync tool, not your normal contacts.

```bash
SKIP_BLOCKED_CONTACTS=true
```

Whether to ignore SimpleLogin contacts that are marked as blocked.
- true: blocked SimpleLogin contacts are not synced into Nextcloud.
- false: blocked contacts still appear in Nextcloud Contacts.

Blocked contacts are usually not useful for composing new mail, so hiding them keeps Apple Mail autocomplete cleaner.

```bash
DEDUPLICATE_CONTACTS_BY_ORIGINAL_EMAIL=true
```

Whether to keep only one reverse alias contact for each original email address, ignoring case, within each SimpleLogin alias.

For example, if SimpleLogin has both `Amanda.Shaw@example.org` and `amanda.shaw@example.org` under the same alias, only the first matching contact returned by the SimpleLogin API is synced. Contacts for the same original email under different SimpleLogin aliases are still kept, because they send from different aliases.

### Alias filters

Disabled SimpleLogin aliases are skipped automatically.

Leave blank to sync all aliases:
```bash
ALIAS_INCLUDE_REGEX=
ALIAS_EXCLUDE_REGEX=
```

Only sync aliases on a custom domain:

```bash
ALIAS_INCLUDE_REGEX=@yourdomain\.com$
```

Exclude throwaway or newsletter aliases:

```bash
ALIAS_EXCLUDE_REGEX=throwaway|newsletter
```

### Reverse alias filters

By default, the sync skips reverse alias email addresses that start with `reply` or `no-reply`:

```bash
REVERSE_ALIAS_EXCLUDE_REGEX=(?i)^(reply|no-reply)
```

The regex runs against the parsed reverse alias email address, such as `reply+abc@example.com`.
Use `(?i)` for case-insensitive matching.

Exclude additional automated senders:

```bash
REVERSE_ALIAS_EXCLUDE_REGEX=(?i)^(reply|no-reply|mailer-daemon|bounce)
```

For longer exclude lists, put one regex fragment per line in a file:

```text
^(?:reply|no-?reply|mailer-daemon|deals?)
@(?:reply|no-?reply|deals?)\.
inform.*@(?:mail|deals?).aliexpress
interest.*@(?:mail|deals?).aliexpress
```

Then mount the file into the container and point the app at the container path:

```yaml
services:
  simplelogin-nextcloud-contacts:
    volumes:
      - ./reverse-alias-exclude-regex.txt:/app/reverse-alias-exclude-regex.txt:ro
```

```bash
REVERSE_ALIAS_EXCLUDE_REGEX_FILE=/app/reverse-alias-exclude-regex.txt
```

Non-empty file lines are joined as case-insensitive alternatives, so the file above is equivalent to:

```bash
REVERSE_ALIAS_EXCLUDE_REGEX=(?i)(^(?:reply|no-?reply|mailer-daemon|deals?)|@(?:reply|no-?reply|deals?)\.|inform.*@(?:mail|deals?).aliexpress|interest.*@(?:mail|deals?).aliexpress)
```

Lines starting with `#` are ignored. If `REVERSE_ALIAS_EXCLUDE_REGEX` and `REVERSE_ALIAS_EXCLUDE_REGEX_FILE` are both set, both filters apply.

Leave the inline regex blank and omit the file path to disable reverse alias exclude filtering:

```bash
REVERSE_ALIAS_EXCLUDE_REGEX=
REVERSE_ALIAS_EXCLUDE_REGEX_FILE=
```

You can also require reverse aliases to match a pattern:

```bash
REVERSE_ALIAS_INCLUDE_REGEX=@simplelogin\.co$
```

### Contact name prefix

```bash
CONTACT_NAME_PREFIX=SL
```

Generated display name format:

```text
SL · Contact Name · Alias Label
```

## Troubleshooting

### Nextcloud authentication failed

Check:

- `NEXTCLOUD_USERNAME`
- `NEXTCLOUD_APP_PASSWORD`
- Whether the app password was copied fully
- Whether your Nextcloud account requires two-factor authentication, in which case app passwords are especially important

### Address book is not created

Check logs for the `MKCOL` failure. If your Nextcloud server blocks address-book creation via CardDAV for some reason, manually create an address book named `SimpleLogin` in Nextcloud Contacts, keep the slug as `simplelogin` if possible, then restart the container.

### Contacts are created in Nextcloud but not Apple Mail

Check:

- Apple device is syncing the Nextcloud Contacts account.
- Contacts app shows the `SimpleLogin` group/address book.
- You are typing the `SL ·` prefix or recipient name in Mail autocomplete.
- CardDAV account is enabled for Contacts, not only Calendars.

### Too many contacts

Use filters:

```bash
ALIAS_INCLUDE_REGEX=@yourdomain\.com$
ALIAS_EXCLUDE_REGEX=newsletter|throwaway
REVERSE_ALIAS_EXCLUDE_REGEX=(?i)^(reply|no-reply|mailer-daemon|bounce)
# Or use REVERSE_ALIAS_EXCLUDE_REGEX_FILE for longer reverse-alias exclude lists.
```

Then restart the container. With `DELETE_STALE=true`, previously generated contacts outside the filter will be removed from the dedicated address book.

### Non-ASCII names look odd

The script writes UTF-8 vCards. If a specific CardDAV client displays names oddly, check the raw vCard in Nextcloud or try a current Apple OS version.

## Updating

After editing files:

```bash
docker compose -f docker-compose.server-sync.yml up -d --build
```

After only editing `.env`:

```bash
docker compose -f docker-compose.server-sync.yml restart simplelogin-nextcloud-contacts
```

## Backup

Before major changes, export or back up the dedicated Nextcloud address book from Nextcloud Contacts.

The script is designed to be disposable and reproducible: if you delete the generated address book, it can recreate contacts from SimpleLogin on the next sync.

## Phase 2 ideas

- Add a small web UI to create a SimpleLogin reverse alias for a new recipient.
- Add a Nextcloud app settings page.
- Add healthcheck endpoint and Prometheus metrics.
- Track ETags and only PUT changed contacts.
- Add per-alias tags or groups.
- Add a manual one-shot mode for cron instead of a long-running container.

## One-shot test command

For debugging, you can temporarily run the container in the foreground:

```bash
docker compose -f docker-compose.server-sync.yml run --rm simplelogin-nextcloud-contacts
```

Stop with `Ctrl+C` after the first sync loop completes.
