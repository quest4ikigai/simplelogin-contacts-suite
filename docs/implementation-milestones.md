# Implementation Milestones

Implemented:

- New repo layout.
- Existing contacts sync moved to `apps/server-sync/`.
- Pure alias routing core with tests.
- SimpleLogin client wrapper with tests.
- Local SQLite cache for aliases and reverse-alias contacts.
- Fail-closed SMTP proxy using `aiosmtpd` for SMTP protocol handling.
- SimpleLogin reverse-alias resolution through cache/API.
- Header/envelope rewrite and upstream SMTP forwarding.
- Docker deployment examples.
- macOS helper design spec.
- iOS-friendly alias selection via exact alias recipients and suffix matching.
- Docker healthcheck / CLI health status.
- Failed-auth delay, max message size, structured audit logs, and cache backup/restore docs.
- Fake SimpleLogin and fake SMTP upstream integration tests.

Remaining future work:

- Manual Apple Mail and iOS shakedown against real Proton Bridge/SimpleLogin accounts.
- Native macOS helper implementation if the documented helper design becomes worth building.
