# Implementation Milestones

Implemented in this pass:

- New repo layout.
- Existing contacts sync moved to `apps/server-sync/`.
- Pure alias routing core with tests.
- SimpleLogin client wrapper with tests.
- Local SQLite cache scaffold.
- Fail-closed SMTP proxy scaffold with tests, using `aiosmtpd` for SMTP protocol handling.
- SimpleLogin reverse-alias resolution through cache/API with fake HTTP tests.
- Header/envelope rewrite and upstream SMTP forwarding with fake upstream tests.
- Docker deployment examples.
- macOS helper design spec.

Remaining major work:

- Wire SimpleLogin client and cache into the SMTP proxy send path.
- Add full fake SimpleLogin and fake upstream SMTP integration tests.
- Add hardening features such as throttling and health checks.
