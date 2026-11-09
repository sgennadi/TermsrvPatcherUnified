# RDPControl source review vs TermsrvPatcherUnified

**Review date:** 2026-11-09  
**Upstream:** [fabianosrc/RDPControl](https://github.com/fabianosrc/RDPControl/tree/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47), commit \`8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47\`.  
**Our baseline:** [TermsrvPatcherUnified](https://github.com/sgennadi/TermsrvPatcherUnified/tree/ea39ceb1aa0b2ade74c4f92a488235de0f36d66e), \`ea39ceb1aa0b2ade74c4f92a488235de0f36d66e\`, v0.1.0-preview.10.  
**Method:** Source-level architectural, safety and UX comparison; no upstream code was copied, and no live TermService/DLL patch test was performed. Conclusions are *hypotheses for engineering and further tests*, not proof of RDP multi-session support, Windows licensing compliance, or safety on an untested build.

## Executive decision

**Do not merge RDPControl itself into the application.** It is a PowerShell 5.1/7 module with a SQLite store and an optional SYSTEM watchdog, whereas TermsrvPatcherUnified is a .NET 10 WPF app with a tightly scoped native write helper, guarded file backups and an independent updater. Adopt selected ideas as new C# implementations, with our own tests and fail-closed behavior. Keep the existing exact-match PE guard and protected backup path.

**Next work, in order:** (P0) mutually exclusive Apply/Restore transactions, (P0) structured read-only DryRun and JSON export, (P1) passive update/drift status with no automatic binary writes, (P1) Windows Terminal Services session inventory, (P1) transactional RDP port settings, (research-only) semantic/disassembly-assisted signature analysis.

## Comparison matrix

| Area | RDPControl (upstream source) | TermsrvPatcherUnified (ours) | Decision |
|---|---|---|---|
| Technology | PowerShell module, modular commands | .NET 10 WPF and self-contained x64 EXE | Keep native UI; do not embed PowerShell runtime |
| Finding patterns | Three-pass heuristic: core byte signature + branch context, REX anchor with target convergence and "CFG-lite", optional session-limit branch | Three embedded exact x64 signature families, guarded unique match, manual fallback and read-only near-match scan | Research structural *inspection*, never port its automatic neutralization unverified |
| Dry-run | Pipeline-friendly rich result includes strategy, offsets, exact proposed bytes, hash, snapshot plan and OS/build | GUI preview/text and opt-in successful fix report including original/result SHA-256 and byte changes | **P0**: structured \`PatchDryRunReport\` in C# + JSON/export; read-only |
| Concurrency | Global named mutex with 30-second timeout and abandoned-lock warning for Apply/Undo | Preview hash verification, but no equivalent cross-process apply/restore mutex | **P0**: add scoped named mutex with secure ACL and explicit timeout/error |
| Backup | SQLite snapshots with BLOB, snapshot IDs, original/enforced markers and audit | \`DllBackupStore\` protected admin-only NTFS directory; checksum-named DLL; Backup on/off, version/size/PE/hash validation | Keep file store. Consider a lightweight **metadata-only** snapshot catalog; not BLOB SQLite |
| In-progress write failure | Multiple in-place patch writes; \`finally\` restores ACL/service, but no evident byte rollback when a later patch write fails | Full-image write with pre/post hash and attempted in-memory rollback on write failure | Keep ours; add fault-injection and verification for multi-error recovery |
| Restore | Reads snapshot BLOB and writes it; SHA-256 verified *after* restore | Validates source before writing; rechecks current hash; guarded rollback on error; admin-only stored backup | Keep ours. Add independent offline recovery instructions and post-restart health checks |
| PE verification | Minimal PE architecture detection; heuristic scans raw byte array | Valid AMD64 PE DLL and all edits must lie wholly inside executable sections | Keep ours; do not relax section/instruction requirements |
| Privilege | Takes ownership and grants current user FullControl, later restores ACL | Scoped NSudo DM, no ownership change or permissive ACL fallback | Keep ours: no ownership/ACL takeover |
| Service lifecycle | Snapshot TermService state; stop and optionally restart in \`finally\` | \`ServiceGuard\` handles TermService, SessionEnv and UmRdpService, remembers previously running | Keep ours, extend failure telemetry; never kill shared svchost |
| Windows policy | RDP enable/disable, port, registry, firewall | RDP enabled, NLA, single-user-session and firewall settings; no port UI | **P1**: optional port settings only with GPO conflict checks and registry/firewall rollback |
| Session inventory | \`qwinsta.exe\` output parsed with a positional text regex | No dedicated live session inventory | **P1**: read-only sessions via native WTS APIs, not locale-sensitive text parsing |
| Watchdog | SYSTEM Scheduled Task may reapply binary edits at boot | No silent scheduled SYSTEM re-patching | **Do not port**. Optional user-invoked *read-only* drift check instead |
| Audit | SQLite audit records and snapshot metadata | Minimal local operation log; approved public v2 hash/byte report, universal diagnostics | **P1**: richer local operation history without tokens, host identifiers in public reports |
| Validation/testing | Substantial Pester unit suite, no upstream Actions workflow in inspected tree; upstream README says Gallery publication pending coverage | Windows Actions with real released EXE upgrade/rollback, read-only real system DLL, real-DLL-copy backup tests | Keep CI; add concurrency/failure-injection tests and Windows 11 VM acceptance |

## Upstream strengths worth adapting (ideas, not source code)

### P0: explicit cross-process operation lock

[Invoke-Enforcement](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Enforcement/Invoke-Enforcement.ps1#L77-L113) and [Undo-Enforcement](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Enforcement/Undo-Enforcement.ps1#L92-L125) use \`Global\RDPControl\` mutex, bounded wait and \`AbandonedMutexException\` handling. Add our own secure \`Global\TermsrvPatcherUnified.Operation\` (or suitable scoped application-wide lock) at the **single mutating entry point**, covering Apply, Restore, and any RDP settings operations that stop TermService. A lock cannot replace rechecking the DLL hash under the lock. Specify proper DACL/owner, documented busy/abandoned messages, and release in \`finally\`. Tests: simultaneous processes cannot both write; timeout does not stop any service; abandoned mutex triggers full revalidation; no deadlock after exceptions.

### P0: structured, deterministic read-only DryRun

[Set-RdpSessionMode](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Policy/Set-RdpSessionMode.ps1#L112-L207) reports source hash, strategy, proposed offsets/bytes, OS build and required snapshot. Our \`PatchPlan\` and \`SuccessfulFixMetadata\` already carry most raw data, but it is not a stable exportable DryRun contract. Add \`PatchDryRunReport/v1\` with schema version, source DLL hash, OS build/UBR, file version, signature/profile provenance, exact before/after bytes, predicted hash, backup availability/decision, PE validity, ambiguity, and readable reasons. **Never include Apply-capable binary replacement instructions as an automatic result for unverified signatures.** Pure read-only scan must not create folders, stop services, change the registry or send to GitHub. Golden JSON output with privacy review and synthetic version-mismatch tests.

### P1: passive drift detection, no auto repair

[Upstream Test-EnforcementState](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Enforcement/Test-EnforcementState.ps1#L44-L74) compares current DLL SHA-256 with the most recent stored enforced snapshot. A passive status such as *Original / Locally changed / Windows replaced DLL / Unknown* would be useful in the GUI. It should compare immutable, locally verified records, display the detection time, and only offer an explicit manual next action. **Do not copy** [SYSTEM boot watchdog](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Watchdog/Start-RdpWatchdog.ps1#L101-L139): auto-reapplication may conflict with Windows Updates and can repeatedly stop RDP services.

### P1: read-only session status in RDP Settings

The author exposes session inventory, but [Get-RdpSession](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Session/Get-RdpSession.ps1#L40-L80) parses \`qwinsta.exe\` console text by a positional regex. We should instead use WTS APIs and native strongly typed session data (session ID, state, user, station), refresh explicitly, honor admin permissions, and default to **read-only**. Any future disconnect/logoff action requires a separate operator confirmation, privilege check, and warning about disruption. Test console/RDP, locked/disconnected states, non-English systems, and 200% DPI.

### P1: snapshot and operation history without a SQLite BLOB store

[SQLite schema](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Store/Providers/SQLite/Initialize-SQLiteProvider.ps1#L26-L44) stores raw full DLL bytes and an audit table. We should keep checksum-named files in protected ProgramData and add a **metadata-only** manifest of successful backup/restore operations (UTC, status, DLL SHA-256/version, saved-copy path basename, source and resulting digest, app version). Do not move DLL bytes into SQLite or allow editing of restore catalog to bypass file verification. Missing/corrupt manifest must never cause unsafe patching.

### Research-only: multi-pass signature/CFG analysis

[Find-BinarySignature](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Assembly/Find-BinarySignature.ps1#L450-L775) has an interesting three-pass strategy with branch relationships and dynamic replacement data. Its broader coverage is **not** proof of correctness: it scans raw byte positions (including potentially non-code bytes), and target convergence is a heuristic rather than a validated control-flow graph. Build any improved classifier as **read-only and report-only** first, with a real instruction decoder, executable-section/RVA checks, basic-block boundaries, and known-good negative fixtures. No automatically generated edits until comprehensive offline corpus validation and manual review prove unique semantics on each supported DLL hash. Keep exact-match fallback and \`Unknown\` if uncertain.

## Concrete upstream failure modes to avoid

1. **Partial binary modification on failure:** [Invoke-Enforcement](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Enforcement/Invoke-Enforcement.ps1#L207-L280) writes each enforcement independently, restoring ACL/service in \`finally\`, but does not visibly restore original binary bytes if a later write fails. A partial patch can remain. Our full-image rollback strategy is safer but still needs controlled failure-injection proof on a VM.
2. **Change ownership / grant FullControl:** [Grant-ProtectedFileAccess](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Engine/Grant-ProtectedFileAccess.ps1#L89-L117) changes ownership and adds a full-control ACE. Even with ACL restoration in the normal flow, process termination mid-operation can leave an unsafe state. Keep our no-takeownership NSudo approach.
3. **Snapshot authenticity:** [Undo-Enforcement](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Enforcement/Undo-Enforcement.ps1#L159-L282) validates the stored BLOB against its recorded SHA **after** writing it to the live DLL, not before. [SECURITY.md](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/SECURITY.md#L95-L101) explicitly says the DB permissions are inherited from ProgramData, without hardening. Our restore validation and protected ACL requirement must remain mandatory.
4. **Heuristic branch decoding:** [Get-ForwardBranch](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Assembly/Find-BinarySignature.ps1#L122-L190) scans each raw byte for branch opcodes, not instruction boundaries; its \`[Convert]::ToSByte(byte)\` path can throw for a rel8 value with its high bit set rather than recognizing a backward branch. Do not treat nearby opcodes or branch convergence alone as a safe patch location.
5. **SQLite cleanup error:** [Initialize-SQLiteProvider](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Store/Providers/SQLite/Initialize-SQLiteProvider.ps1#L59-L64) closes a connection only when \`$connection -eq $null\`, i.e. the condition appears inverted. Do not copy this resource-lifetime implementation.
6. **Locale-dependent session parsing:** the [qwinsta regex](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Session/Get-RdpSession.ps1#L53-L72) assumes fixed whitespace, headers and column positions; a native API is preferable.
7. **Non-transactional RDP port update:** [Set-RdpPort](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Policy/Set-RdpPort.ps1#L90-L111) changes registry, firewall, and service sequentially without visibly restoring earlier settings when a later step fails. Our current \`RdpConfiguration.Save\` likewise updates settings sequentially; this is an improvement target for **our** code too.
8. **SYSTEM auto-repatch:** task generated by [New-WatchdogTaskAction](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Private/Engine/New-WatchdogTaskAction.ps1#L46-L56) runs PowerShell with \`-ExecutionPolicy Bypass\`; [Watchdog](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/src/Public/Watchdog/Invoke-RdpWatchdog.ps1#L69-L116) can automatically re-apply binary changes. Do not add unattended re-patching.

## Acceptance gates before considering integration

| Priority | Deliverable | Minimum acceptance |
|---|---|---|
| P0 | Secure named operation mutex | Two independent processes; only one Apply/Restore reaches any service stop; abandoned lock revalidates SHA; timeout produces no writes |
| P0 | JSON/read-only DryRun schema | Stable versioned output; exact original/result hashes for verified previews; no network, backups, RDP interruption or registry writes; deterministic fixtures |
| P1 | Passive DLL drift/status | No SYSTEM task; detects changed-on-disk hash; never auto-patches or restarts service; explicit refresh and user review |
| P1 | Native WTS session inventory | No \`qwinsta\` regex; non-English Windows/empty/console/disconnected sessions covered; read-only by default |
| P1 | Safe RDP port UI | Validate port, registry and firewall; show GPO conflicts; transactional rollback on failure and preserve original service state |
| Research | Semantic signature evaluator | Read-only only; actual decoder and PE code-range proof; full positive/negative fixture corpus; Unknown on ambiguity and unsupported versions |

## Explicit non-goals

- No copying another project's binary patch table or taking "more matches" as evidence of correctness.
- No unattended scheduled SYSTEM repair, automatic post-Windows-Update repatching, silent privilege escalation or service interruptions.
- No conversion to PowerShell, no new SQLite dependency for full system DLL BLOBs, and no automatic broadening to x86/Windows Server.
- No assumption that a successful static signature scan guarantees a working connection or licensing entitlement.

## Attribution / licenses

RDPControl repository is [Apache License 2.0](https://github.com/fabianosrc/RDPControl/blob/8da0b2587d1ca8cf5f82ad66c9a4fa320afdaf47/LICENSE); our repository is GPLv3. **This review adds no third-party code**. Future direct code reuse would require a separate licensing/notice review. Prefer independent C# implementations of general engineering concepts, with our own validation and tests.
