# Docker Deployment

This folder contains Docker deployment files for the apps in this repo. The SMTP
proxy is the outgoing SMTP server for Apple Mail; IMAP should stay pointed
directly at Proton Mail Bridge. The server-sync app optionally syncs
SimpleLogin reverse aliases into Nextcloud Contacts.

## Files

- `docker-compose.smtp-proxy.yml`: SMTP proxy only.
- `docker-compose.server-sync.yml`: Nextcloud contacts sync only.
- `docker-compose.full.yml`: SMTP proxy plus the optional Nextcloud contacts sync.
- `.env.smtp-proxy.example`: SMTP proxy environment template.
- `.env.server-sync.example`: Nextcloud contacts sync environment template.

## Simple Step-By-Step Usage

1. Copy the environment template:

```bash
cd deploy/docker
cp .env.smtp-proxy.example .env
```

2. Edit `.env` and set at least:

```dotenv
SIMPLELOGIN_API_KEY=...
SMTP_PROXY_USERNAME=...
SMTP_PROXY_PASSWORD=...
SMTP_PROXY_REQUIRE_TLS=true
SMTP_PROXY_TLS_MODE=starttls
SMTP_PROXY_TLS_CERT_FILE=/certs/proxy.crt
SMTP_PROXY_TLS_KEY_FILE=/certs/proxy.key
UPSTREAM_SMTP_HOST=host.docker.internal
UPSTREAM_SMTP_PORT=1025
UPSTREAM_SMTP_USERNAME=...
UPSTREAM_SMTP_PASSWORD=...
UPSTREAM_SMTP_TLS_MODE=none
UPSTREAM_SMTP_TLS_VERIFY=true
USER_MAILBOXES=user@example.com
ALIAS_SUFFIX_DOMAINS=@example.net,@subdomain.simplelogin.example,.suffix@simplelogin.example
```

Secret values can also be read from mounted files. Direct variables take
precedence when both forms are set, so leave the direct value empty or unset
when using the `_FILE` variant:

```dotenv
SIMPLELOGIN_API_KEY=
SIMPLELOGIN_API_KEY_FILE=/run/secrets/simplelogin-smtp-proxy/simplelogin_api_key
SMTP_PROXY_USERNAME=
SMTP_PROXY_USERNAME_FILE=/run/secrets/simplelogin-smtp-proxy/smtp_proxy_username
SMTP_PROXY_PASSWORD=
SMTP_PROXY_PASSWORD_FILE=/run/secrets/simplelogin-smtp-proxy/smtp_proxy_password
UPSTREAM_SMTP_USERNAME=
UPSTREAM_SMTP_USERNAME_FILE=/run/secrets/simplelogin-smtp-proxy/upstream_smtp_username
UPSTREAM_SMTP_PASSWORD=
UPSTREAM_SMTP_PASSWORD_FILE=/run/secrets/simplelogin-smtp-proxy/upstream_smtp_password
```

Create the local secret files and mount the directory read-only:

```bash
mkdir -p secrets
printf '%s\n' 'your-simplelogin-api-key' > secrets/simplelogin_api_key
printf '%s\n' 'your-proxy-smtp-username' > secrets/smtp_proxy_username
printf '%s\n' 'your-proxy-smtp-password' > secrets/smtp_proxy_password
printf '%s\n' 'your-upstream-smtp-username' > secrets/upstream_smtp_username
printf '%s\n' 'your-upstream-smtp-password' > secrets/upstream_smtp_password
chmod 600 secrets/*
```

Then uncomment this volume in `docker-compose.smtp-proxy.yml`:

```yaml
- ./secrets:/run/secrets/simplelogin-smtp-proxy:ro
```

You do not need to list every SimpleLogin alias. The proxy discovers your owned
aliases from the SimpleLogin API and stores them in the SQLite cache at
`CACHE_PATH`. Use `MANUAL_SIMPLELOGIN_ALIASES` only for temporary local
overrides.

3. Keep this enabled for the first test:

```dotenv
SMTP_PROXY_DRY_RUN=true
```

4. Start the proxy:

```bash
docker compose -f docker-compose.smtp-proxy.yml up -d --build
docker logs -f simplelogin-smtp-proxy
```

The `smtp-proxy` service includes a Docker healthcheck that connects to the
local SMTP listener and verifies it returns a ready banner.

Docker applies healthcheck changes only when the container is created. If
`docker inspect simplelogin-smtp-proxy --format '{{json .State.Health}}'`
prints `null`, recreate the service after pulling this compose file:

```bash
docker compose -f docker-compose.smtp-proxy.yml up -d --build --force-recreate smtp-proxy
```

5. Send a dry-run test message through the proxy. The message should be rejected
   after a redacted transform summary is logged.

For manual alias selection today, place exactly one alias in `To`, `Cc`, or `Bcc`:

```text
Cc: orders@example.net
```

The proxy matches the alias against `ALIAS_SUFFIX_DOMAINS` or the discovered owned-alias cache, verifies it with SimpleLogin, uses it for reverse-alias routing, and strips that alias recipient before forwarding. If two distinct aliases appear anywhere in the submitted recipients, the proxy rejects the message.

Supported suffix examples:

```dotenv
ALIAS_SUFFIX_DOMAINS=@example.net,@subdomain.simplelogin.example,.suffix@simplelogin.example
```

6. When the dry-run log shows the expected selected alias and rewritten
   recipient count, switch only for a controlled test:

```dotenv
SMTP_PROXY_DRY_RUN=false
```

7. Restart and send to a disposable/test recipient:

```bash
docker compose -f docker-compose.smtp-proxy.yml up -d
```

8. After the test, inspect logs and confirm the upstream recipient was a
   SimpleLogin reverse alias, not the original external address.

## Deployment Modes

### Mode A: Same Mac As Apple Mail

```text
Apple Mail -> localhost:2525 -> SMTP proxy -> Proton Bridge SMTP
```

Use this for first tests. Bind to localhost if Docker networking allows it:

```dotenv
SMTP_PROXY_HOST=127.0.0.1
SMTP_PROXY_PORT=2525
SMTP_PROXY_REQUIRE_AUTH=true
SMTP_PROXY_REQUIRE_TLS=false
SMTP_PROXY_AUTH_FAILURE_DELAY_SECONDS=1.0
SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN=true
```

The unsafe local dry-run escape hatch only works for loopback binds with
`SMTP_PROXY_DRY_RUN=true`. If Docker Desktop needs the container to listen on
`0.0.0.0`, configure inbound TLS, non-default SMTP credentials, and
`USER_MAILBOXES`; the proxy refuses remote-capable binds with local-only safety
shortcuts.

### Mode B: Home Server Over VPN

```text
Mac/iPhone/iPad -> Tailscale/WireGuard -> home server proxy -> Proton Bridge SMTP
```

Recommended for daily cross-device use. Keep the proxy reachable only on your
VPN interface or trusted LAN:

```dotenv
SMTP_PROXY_HOST=0.0.0.0
SMTP_PROXY_REQUIRE_AUTH=true
SMTP_PROXY_REQUIRE_TLS=true
SMTP_PROXY_TLS_MODE=starttls
SMTP_PROXY_TLS_CERT_FILE=/certs/proxy.crt
SMTP_PROXY_TLS_KEY_FILE=/certs/proxy.key
```

Use Tailscale/WireGuard ACLs or firewall rules so the port is not public. If
Apple Mail sends encrypted bytes immediately on connect instead of issuing
`EHLO` and `STARTTLS`, switch this listener to `SMTP_PROXY_TLS_MODE=implicit`
or run a second dedicated implicit-TLS listener on a separate port.

### Mode C: Public TLS Endpoint

Use this only if VPN is not practical.

Requirements before public exposure:

- TLS with a valid certificate.
- SMTP AUTH enabled with a strong password.
- Failed-auth throttling or firewall-level rate limiting.
- Monitoring for auth failures.
- `ALLOW_DIRECT_EXTERNAL_SEND=false`.

The proxy supports inbound STARTTLS and implicit TLS with configured certificate
and key files. Do not expose it publicly unless the certificate is valid for the
client-facing hostname and firewall/rate-limit controls are in place.

## Upstream SMTP TLS

Use `UPSTREAM_SMTP_TLS_MODE` to control the proxy-to-upstream hop:

```dotenv
UPSTREAM_SMTP_TLS_MODE=none
UPSTREAM_SMTP_TLS_VERIFY=true
```

Supported modes are `none`, `starttls`, and `implicit`. Use `starttls` for
port 587-style submission and `implicit` for port 465-style SMTPS.

Certificate and hostname verification are enabled by default for upstream TLS.
Set `UPSTREAM_SMTP_TLS_VERIFY=false` only for a trusted self-signed upstream,
such as a private bridge or test SMTP server that you control.

## Apple Mail On macOS

Keep incoming mail unchanged:

- Incoming/IMAP server: Proton Mail Bridge IMAP.

Change only outgoing mail:

1. Open Mail settings.
2. Go to Accounts.
3. Select the Proton account.
4. Open Server Settings.
5. Keep Incoming Mail Server pointed at Proton Bridge IMAP.
6. Set Outgoing Mail Server to a custom SMTP server.
7. Hostname: proxy host, such as `127.0.0.1` or your VPN hostname.
8. Port: `2525` unless changed.
9. Username/password: `SMTP_PROXY_USERNAME` and `SMTP_PROXY_PASSWORD`.
10. TLS: off only for same-host localhost tests. For remote clients, enable
    TLS/SSL and set the proxy to `SMTP_PROXY_TLS_MODE=starttls` or
    `SMTP_PROXY_TLS_MODE=implicit`, whichever matches the client behavior.

Alias selection options:

- `X-SimpleLogin-Alias` from a future helper.
- Exactly one alias in `To`, `Cc`, or `Bcc`, such as `Cc: orders@example.net`, when its suffix is listed in `ALIAS_SUFFIX_DOMAINS` or it is discovered from SimpleLogin.
- Single `To` alias cover recipient for anonymized Bcc sends, such as
  `To: announcements@example.net` plus external recipients in Bcc.

If two distinct aliases appear anywhere in the submitted recipients, the proxy rejects the message.

For the cover-recipient flow, the proxy preserves the alias in the visible `To`
header, removes that alias from the SMTP envelope, strips `Bcc`, and forwards
only the rewritten SimpleLogin reverse aliases for the Bcc recipients.

Owned aliases for reply-all cleanup are discovered from SimpleLogin
automatically; do not maintain a giant comma-separated alias list in `.env`.

## iOS And iPadOS Mail

Use a trusted network path, preferably Tailscale or WireGuard.

1. Open Settings.
2. Go to Apps, then Mail, then Mail Accounts. Labels vary by iOS version.
3. Select the Proton account.
4. Open SMTP / Outgoing Mail Server.
5. Add or edit the primary SMTP server.
6. Hostname: proxy VPN hostname or trusted LAN hostname.
7. Port: `2525` unless changed.
8. Username/password: `SMTP_PROXY_USERNAME` and `SMTP_PROXY_PASSWORD`.
9. Use SSL/TLS with a proxy certificate trusted by the device.
10. Keep incoming IMAP pointed directly at Proton Bridge or your existing
    incoming-mail setup.

For alias selection on iOS, place exactly one alias in `To`, `Cc`, or `Bcc`, such as `Cc: orders@example.net`, when its suffix is listed in `ALIAS_SUFFIX_DOMAINS` or it is discovered from SimpleLogin.

The proxy consumes and strips the alias recipient before forwarding, except for the single-`To` cover-recipient flow where the visible `To` alias is preserved and removed only from the SMTP envelope.

## Safe Defaults

Recommended values:

```dotenv
SMTP_PROXY_REQUIRE_AUTH=true
SMTP_PROXY_DRY_RUN=true
SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN=false
SMTP_PROXY_AUTH_LOGIN_ENABLED=true
SMTP_PROXY_AUTH_FAILURE_DELAY_SECONDS=1.0
FAIL_CLOSED=true
KEEP_UNKNOWN_SIMPLELOGIN_ADDRESSES=true
STRIP_OWN_ALIASES=true
STRIP_OWN_MAILBOXES=true
ALLOW_DIRECT_EXTERNAL_SEND=false
LOG_REDACT_ADDRESSES=true
LOG_MESSAGE_BODY=false
LOG_SUBJECT=false
```

Do not run an unauthenticated public SMTP relay. Do not set
`ALLOW_DIRECT_EXTERNAL_SEND=true` for normal use.

## Audit Logs

The proxy writes structured audit events as log lines prefixed with `audit`.
These events include policy outcomes and counts, not message bodies, subjects,
attachments, API keys, SMTP passwords, or raw recipient lists.

Example:

```text
audit {"drop_count":1,"event":"smtp_transform_plan","keep_count":0,"peer":"127.0.0.1","reason":"none","reject_count":0,"rejected":false,"rewrite_count":1,"selected_alias":"o***s@example.net","selected_alias_source":"alias_selector"}
```

Use normal Docker logs to inspect them:

```bash
docker logs simplelogin-smtp-proxy
```

## Healthcheck History And Uptime Kuma Monitoring

Docker stores a small rolling history of healthcheck executions on the
container. This is useful for the most recent failure, but it is not a durable
multi-day log and healthcheck output is not copied into `docker logs`.

Inspect Docker's native health state:

```bash
docker inspect --format '{{json .State.Health}}' simplelogin-smtp-proxy | jq .
```

Print the recent native healthcheck outputs:

```bash
docker inspect --format '{{range .State.Health.Log}}{{.Start}} exit={{.ExitCode}} {{.Output}}{{println}}{{end}}' simplelogin-smtp-proxy
```

The proxy also writes durable JSONL health history to the `/data` volume by
default:

```bash
docker exec simplelogin-smtp-proxy sh -c 'tail -n 100 /data/healthcheck.jsonl'
```

If the container is stopped or has been removed but the volume still exists,
inspect the volume directly. The default compose project name for this folder is
`docker`, so the volume is usually `docker_smtp_proxy_data`:

```bash
docker run --rm -v docker_smtp_proxy_data:/data busybox tail -n 100 /data/healthcheck.jsonl
```

The history file rotates to `/data/healthcheck.jsonl.1` when it reaches
`SMTP_PROXY_HEALTHCHECK_HISTORY_MAX_BYTES`, which defaults to 5 MiB.
The Docker healthcheck timeout is intentionally longer than
`SMTP_PROXY_HEALTHCHECK_TIMEOUT_SECONDS` so timeout failures can still be
recorded before Docker stops the probe process.

Use Uptime Kuma as the notification layer instead of putting notification
credentials in the SMTP proxy. Recommended monitors:

- Docker Container monitor for `simplelogin-smtp-proxy`, using the Docker
  health state produced by this compose healthcheck.
- TCP Port monitor against the host and port your mail clients use, such as the
  VPN/LAN hostname on port `2525`.

For a Docker Container monitor, Uptime Kuma needs access to the Docker daemon,
commonly by mounting `/var/run/docker.sock` into the Uptime Kuma container. That
socket grants broad control over Docker, so keep Uptime Kuma private to your VPN
or trusted LAN and do not expose it to the public internet when using Docker
monitoring. See the Uptime Kuma Docker monitor guide:

```text
https://github.com/louislam/uptime-kuma/wiki/How-to-Monitor-Docker-Containers
```

Configure Pushover in Uptime Kuma's notification settings, then attach that
notification to the Docker Container and TCP Port monitors. If Uptime Kuma runs
on the same headless server, it can detect proxy/container failures but cannot
notify you when the whole server, Docker host, or network path is down. For that
failure mode, run Uptime Kuma somewhere outside the server's failure domain or
add an external monitor for the server/VPN endpoint.

## Cache Backup And Restore

The SQLite cache lives at `CACHE_PATH`, which defaults to `/data/cache.sqlite3`
inside the container and is stored on the `smtp_proxy_data` Docker volume.

Back up the cache:

```bash
docker cp simplelogin-smtp-proxy:/data/cache.sqlite3 ./cache.sqlite3.backup
```

Restore the cache:

```bash
docker stop simplelogin-smtp-proxy
docker cp ./cache.sqlite3.backup simplelogin-smtp-proxy:/data/cache.sqlite3
docker start simplelogin-smtp-proxy
```

If you lose the cache, the proxy can rebuild owned aliases and recently needed
reverse-alias contacts from SimpleLogin. A backup mainly avoids extra API calls
and preserves cached recently used contacts after a host or volume migration.

## Useful Commands

Start or rebuild:

```bash
docker compose -f docker-compose.smtp-proxy.yml up -d --build
```

View logs:

```bash
docker logs -f simplelogin-smtp-proxy
```

Stop:

```bash
docker compose -f docker-compose.smtp-proxy.yml down
```

Run the contacts sync only:

```bash
cp .env.server-sync.example .env
docker compose -f docker-compose.server-sync.yml up -d --build
```

Run the full example with the SMTP proxy plus contacts sync:

```bash
cp .env.smtp-proxy.example .env
# Append the server-sync settings you need from .env.server-sync.example.
docker compose -f docker-compose.full.yml up -d --build
```
