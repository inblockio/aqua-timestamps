# Operational Readiness

**Current Level:** ORL-2 (Development)
**Last Assessed:** 2026-05-20
**Assessed By:** tim.bansemer@inblock.io

## Status

aqua-timestamp is a deployed, actively maintained timestamping service
dual-anchoring to Sepolia (EVM) and Sectigo Qualified TSA (eIDAS).
The service is functional but lacks security hardening, monitoring,
and verified backup procedures.

## ORL-2 Criteria (met)

- [x] Active maintainer assigned
- [x] Source code in version control with branch protection
- [x] CI pipeline runs on every PR (GitHub Actions)
- [x] README documents how to run and develop locally
- [x] Deployment is reproducible (Docker)
- [x] Known security gaps documented (see below)
- [ ] Manual or automated backups exist (fjall state not backed up)

## Unmet Criteria for ORL-3 (Pre-production)

- [ ] Security review completed or in progress
- [ ] Backup and restore procedure verified
- [ ] Monitoring and alerting active (health checks, error rates)
- [ ] API stability commitment (no breaking changes without migration)
- [ ] Test coverage on critical paths (59 tests, but no fuzz/property)
- [ ] Dependency audit completed (no known critical CVEs verified)
- [ ] Logging sufficient for incident investigation

## Known Security Gaps

- No rate limiting per DID
- No input size limits beyond max_leaves_per_request
- fjall keyspace not encrypted at rest
- No WAL for accumulator (data loss on crash between seal cycles)

## History

| Date | Level | Notes |
|---|---|---|
| 2026-05-17 | ORL-1 | Initial deployment (M0) |
| 2026-05-17 | ORL-2 | M1-M5 shipped, CI added, Docker reproducible |
