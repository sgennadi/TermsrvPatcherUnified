# Security remediation (2026-11-21)

## Scope and current limitations

- GitHub release asset digests are not a substitute for an independently signed binary. Automatic/self-update must not be used with elevated trust until the installed application has an embedded signing-key pin and validates the signed EXE before any replacement.
- Report aggregation now gates the workflow on the existing gateway's GitHub login (`sgennadi`). Use a dedicated bot identity with a narrowly scoped Issues-only token as the next step; change the allowlist when it is deployed.
- Diagnostic/compatibility CSV content is UNVERIFIED evidence, never proof of successful remote access, and must not drive Apply.
- A public anonymous Apps Script URL cannot be secured by hiding or rotating it. Exhaustion of per-day quotas remains possible; isolate projects and add upstream rate limiting or a durable queue.
- Move the Microsoft365AuthRepair gateway to its own repo/deployment before deleting the existing code. A GitHub commit does not update live Google Apps Script deployments.

## GitHub owner settings required

Under Settings → Rules → Rulesets, protect `main`: require reviewed pull requests, passing CI and CodeQL, block direct or force pushes, prevent bypasses except a tightly scoped maintenance identity, and protect release tags. The current repository has `main.protected=false`; source-controlled workflows cannot enforce admin rules.

## Release signing owner steps (not yet complete)

1. Provision an offline code-signing key outside GitHub, GitHub Actions and the Apps Script gateway.
2. Sign the release EXE using Authenticode and timestamp it.
3. Pin the signing public key in the already trusted updater; require both signature validation and matching pinned signer before staging, replacement, SYSTEM worker refresh and rollback use.
4. Bootstrap the first protected updater out-of-band; existing vulnerable/unsigned clients cannot authenticate this transition.
5. Test malicious GitHub asset replacement, writable install folders and race conditions on a disposable Windows VM.

This PR implements workflow gating and static-analysis automation; it does **not** claim release signing, DoS resistance, or runtime tests are complete.
