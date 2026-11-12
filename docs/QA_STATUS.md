## Preview 1.0.7-preview.1 — clear installed DLL state (published 2026-11-12)

- **Bug:** Simple Mode previously preferred the text "Verified original available for Revert" over the current exact-signature result. Thus a recoverable patched DLL did not clearly say "PATCHED".
- **Fix:** Simple and Advanced have a prominent independent DLL status: PATCHED (verified replacement evidence), NOT PATCHED (known original-side signature), or UNKNOWN (unsupported, ambiguous, conflicting or failed inspection). A matching Find signature alone does **not** authenticate Microsoft provenance.
- **Separate capability:** Revert readiness is shown independently and requires an exact current DLL SHA-256 and file-version-bound recovery. A recovery source with conflicting current signature evidence fails closed, disables Apply/Revert, and never overrides the DLL-status label.
- **Freshness:** quick check independently hashes current installed DLL after recovery inspection; Apply/Revert invalidate any previous status until a fresh check. No display-only status authorizes write permissions or changes protected files.
- **Verified gates:** [PR Windows 2025 CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43229584371), [main Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43230056079), [Preview publisher](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43230056078) and [published EXE replacement/rollback](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43230056190) succeeded. [Preview 1.0.7-preview.1](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.7-preview.1) is marked prerelease; Latest Stable remains 1.0.6. Real RDP connections and Windows Update Auto Reapply are not tested by this change.

## Stable 1.0.6 — release acceptance (published 2026-11-12)

- Combines protected Session 0 worker/ACL hardening from Preview.1 and read-only RDP Doctor/Firewall improvement from Preview.2.
- Prior acceptance: [Preview.1 Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43059718996), [Preview.2 Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43086615656) and [Preview.2 publication](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43086615648) succeeded.
- **Release gates passed:** [PR Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43163214647) and [Stable publisher](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43163485075) completed Windows 2025 compilation, synthetic Firewall/RDP/WPF/update tests, EXE ProductVersion, two no-DLL-write SYSTEM/Session 0 probes and exact three-asset [Stable 1.0.6](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.6) verification.
- New regression matrix tests Preview.2 → Stable 1.0.6 upgrade plus rejection of equal/older Preview/Stable. All EXE replacements require administrator approval and rollback.
- CI does not modify a production Firewall or system DLL and does not verify physical Windows 11 RDP reconnect, live Windows Update Auto Reapply, or 200% display rendering on a physical screen.

## Preview 1.0.6-preview.2 — RDP Doctor statuses and Firewall regression (published 2026-11-11)

- **Trust model:** local facts have separate Verified locally / Observed locally states; incomplete enumeration, unavailable sources and deliberately Not tested external connectivity are distinct from each other. No local observation is a remote sign-in claim.
- **Firewall:** exact configured TCP port and active Domain/Private/Public profile, enabled Allow/Block candidates, custom exact-port rules. COM failure falls back to read-only limited CIM and registry evidence and must never show Verified locally.
- **Tests:** pure port, range, protocol, action, profile and partial-result tests; synthetic Doctor classification; local-only raw Firewall/LSA/certificate information excluded from Copy safe report; WPF six-card layout and colored read-only table.
- **Verified gates:** [PR Windows 2025 CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43086119000), [main Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43086615656) and [Preview publisher](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43086615648) passed; [Preview 1.0.6-preview.2](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.6-preview.2) contains the expected ZIPs and checksum manifest. No protected DLL or Firewall policy writes, live Windows 11 RDP authentication, or physical 200% DPI claimed.

## Preview 1.0.6-preview.1 — SYSTEM/Session 0 scheduler ACL acceptance (published 2026-11-11)

- Issue [#25](https://github.com/sgennadi/TermsrvPatcherUnified/issues/25): an older non-destructive Windows CI probe intermittently recorded only `UnauthorizedAccessException` with no stage label. Resolved for the published Preview; this is test-hardening, not a new patch pattern or a new Stable build.
- The isolated Apply, Revert and probe staging paths now create a **new** protected executable stream under an already validated private administrator/SYSTEM directory rather than carrying over source file ACL metadata with `File.Copy`. Original and staged executable hashes must match; partially staged files are removed on failure.
- The staged executable, request metadata and atomically written status files must have allow ACEs for **SYSTEM and Administrators only**; an untrusted user ACE fails closed. Pure unit tests cover acceptable and rejected file DACLs.
- The SYSTEM probe failure status records a **fixed stage name and exception type only**, not machine identifiers, account names, paths, tokens or exception messages. CI performs two separate one-shot non-destructive probes per run.
- **Verified gates:** [final PR CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43059232023), [main CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43059718996), and [Preview 1.0.6 publication](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/43059719474) passed. The [published Preview](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.6-preview.1) is unsigned; the latest Stable remains 1.0.5. This change does **not** test a real Windows 11 DLL modification, RDP reconnect, or closing the RDP GUI during an operation. No such success is claimed.

## Stable 1.0.5 acceptance — 2026-11-11

- **Real operator-approved reporting:** Windows 11 26H2 Apply metadata from Preview.4 was delivered through Google Apps Script into [general diagnostic Issue #46](https://github.com/sgennadi/TermsrvPatcherUnified/issues/46) and a [DLL compatibility Issue #1 comment](https://github.com/sgennadi/TermsrvPatcherUnified/issues/1). The collector added one entry to `data/successful-fixes.csv`, without independently validating an RDP connection. The operator confirmed Unified Apply report closes after the successful send.
- **Version downgrade guard:** tests cover installed Stable `1.0.5` vs `1.0.5-preview.5`, `1.0.5-preview.99`, older 1.0.4, equal 1.0.5 and explicitly approved newer versions. GUI staging and protected updater helper share the strict SemVer gate. Preview GitHub releases are always `--latest=false`.
- **Final Stable gates:** Windows 2025 build, source/Google schema checks, WPF UI, DLL compatibility, offline DLL, backups, operation lock, RDP, EXE inspection and non-destructive SYSTEM execution run before publication; exactly 3 release assets are checked after publication.
- **Not yet validated live:** unattended Auto Reapply after Windows Update, isolated physical RDP reconnection on all supported Windows builds and physical 200% DPI. Those require separate authorized machines and are not implied by public self-reports.

## Partial Google reporting and automatic close — 1.0.5-preview.5 candidate

- **Reproduction:** Preview.4 posted the combined general diagnostics to Issue #43, but Google did not acknowledge an Issue #1 DLL compatibility comment. The UI correctly remained open and must not record automatic reporting consent on partial success.
- **Fix:** Two independently validated receipts control successful close. In the same window, a failed second step leaves the first Issue receipt in memory; a manual retry shows only the pending compatibility JSON, obtains fresh approval, sends only that record and closes on its confirmed comment URL. A new EXE process does not implicitly trust/reuse an old in-memory receipt.
- **Diagnostics:** The UI shows the safe Google error explanation instead of only `InvalidOperationException`, including receiver deployment checks and Issues-write permission guidance. GET now provides a public, read-only version/schema indicator after owner redeployment.
- **Tests:** synthetic 2-POST partial failure + 1-POST compatibility retry, no duplicate diagnostic POST, receipt-state policy, gateway GET health, strict public data grammar and WPF review rendering. Neither live GitHub postings nor protected DLL changes run in CI.

## WinBuild DLL version and retrospective report recovery — 1.0.5-preview.4 candidate

- **User reproduction:** Win11 26H2 / termsrv.dll `10.0.26100.8115 (WinBuild.160101.0800)`: protected SYSTEM Apply can complete successfully while the strict public report validator rejects the WinBuild suffix and saves a status with `Report=null`; the Simple/Advanced GUI consequently has no consent prompt.
- **Fix:** retain raw DLL resource text in Windows, request and DPAPI journal for exact matching; canonicalize only the public metadata to the numeric `10.0.26100.8115`. Parse the source staged EXE ProductVersion, not the currently executing updater version.
- **Recovery:** for a completed one-shot SYSTEM task with no embedded report, verify the job request, ID, terminal status, secure directories, original/executable SHA-256, current DLL SHA-256 and DPAPI-protected edited bytes, including their executable section. Reconstruct a report **without any new Apply**; unresolved evidence fails closed and cannot upload.
- **Regression:** synthetic WinBuild variants, exact byte replay, tampering rejection, staged EXE version and WPF report workflow. No real Windows protected DLL is modified by CI.

## Unified RDP post-Apply report recovery — 1.0.5-preview.3 candidate

- A one-shot SYSTEM task now records a bounded, validated `SuccessfulFixMetadata` only after successful Apply and verified final DLL SHA-256. The UI reconstructs it after RDP disconnect and GUI restart without re-running Apply or guessing edited bytes.
- Simple and Advanced independently verify the persisted job request, ID, state, original/result SHA-256, Windows/DLL build evidence and the current installed DLL SHA-256 before showing the report window. A durable once-per-job offer marker prevents repeated unsolicited prompts; a manual Share button remains available after dismissal.
- The unattended Windows-Update Auto Reapply worker uses separate state and cannot trigger an interactive offer. Jobs from previous builds without validated evidence, failed tasks or AlreadyPatched are not offered.
- Ordinary diagnostics closes after confirmed Google-to-GitHub delivery; no successful close on an unverified response. Synthetic .NET, Windows UI and published EXE checks are required; no actual protected DLL write or live reconnect is claimed.

## Unified and silent Auto Reapply report QA — feature branch

- A combined manual report presents typed diagnostics and DLL compatibility in one read-only preview with one approval, while the receiver stores them in two independent public GitHub record classes.
- The unchecked-by-default consent is saved only after both manual receipts succeed; consent is protected, endpoint-bound, revocable, and checked by the SYSTEM worker after a successful SHA-256-verified Apply. No progress or failure dialogs appear in Session 0.
- Synthetic tests cover absent/invalid/disabled consent, endpoint mismatch, non-SYSTEM context, manual/AlreadyPatched/failed checksums, read-only preview, and revocation controls. Windows GitHub Actions must pass before publishing or merging; no actual patch or live Google auto-send is asserted.

## Compatibility Google relay QA — 1.0.5 candidate

- New synthetic .NET fake-HTTP checks: exact approved JSON, no client token, explicit GitHub Issue #1 comment receipt, edited/mismatched JSON refusal and rejection of unrelated/malicious comment URLs.
- New offline Node 24 Apps Script VM checks: strict schema and SHA/edit validation, public comment delivery, event-id dedup, existing diagnostic Issue backward compatibility, missing server token failure. No external network calls.
- New WPF offscreen checks: consent-only report UI for console Apply and offline copy has no GitHub token field; the output remains read-only.
- GitHub Actions aggregators separately run their Python self-tests before accepting public comment events. No live Google deployment, public Issue comment, functional Windows 11 RDP or physical 200% DPI is asserted.
- **Owner must redeploy Google Apps Script** as a new version to enable this path; the current EXE does not update the hosted code.

## Unified Remote Desktop / RDP Doctor — 1.0.5 candidate

- The standalone RDP Doctor tab was merged into Remote Desktop; only one Run RDP Doctor scan button exists.
- The prioritized findings, local event metadata and detailed Firewall, logon rights, TLS certificate and graphics boxes are populated from the same read-only inspection; the old separate Inspect button was removed.
- WPF smoke checks single-tab topology, default-collapsed panels, read-only grids and no duplicate inspector button. Synthetic Doctor report checks local identity/certificate details remain excluded from text export.
- Windows CI must pass at final PR head before merging; this does not validate live Windows 11 remote connections or real 200% DPI hardware.

# DLL compatibility-index QA (1.0.5 feature branch; NOT RELEASED)

The offline, non-destructive compatibility-index test command `--dll-compatibility-qa` validates exact version/SHA matching, missing/malformed data, self-report trust boundaries and path-free exports. Windows CI is required before publishing. The approved Stable release is 1.0.4. Real RDP sessions, Windows servicing and 200% physical DPI are not validated by the offline test.

# QA status — 2026-11-10

## Stable 1.0.0 — published

- [Pre-version alignment Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42849738314) passed source validation, .NET 10 compilation, signed-off synthetic signature/PE and RDP checks, backup/rollback, WPF creation/layout smoke tests and a non-destructive SYSTEM/Session 0 executor probe. **This is not evidence that real RDP sessions were exercised.**
- [Version-aligned final Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42851133298), [main-branch CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42851593054), and [Stable release gate](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42851593018) passed. [v1.0.0](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.0) was published with verified exact release asset names and a SHA-256 manifest.
- [Diagnostic Issue #32](https://github.com/sgennadi/TermsrvPatcherUnified/issues/32) confirms delivery of an operator-approved Google Apps Script → GitHub report. The Windows/DLL evidence remains unverified and never changes active patch patterns.
- The Updates button badge on both Simple and Advanced is informational; cached results cannot authorize Install. Users must review a verified live package and explicitly approve replacement.
- CI **does not** validate protected System32 writes, RDP disconnection and reconnection, a real Windows Update with Auto Reapply enabled, or physical 200% DPI screenshots. These require isolated authorized VM tests with independent console recovery.
- Auto Reapply remains off by default. Unknown, ambiguous or mismatching signatures are not automatically patched.

## 0.1.0-preview.23 — isolated Windows CI only

- Windows 2025 pipeline runs compiler, synthetic signature and rollback tests, WPF layout smoke, update-archive packaging validation and a one-shot non-destructive SYSTEM worker probe.
- The new persistent Auto Reapply event/boot/daily task has *not* been activated or validated end-to-end on an actual Windows 11 client. No real termsrv.dll service write, reboot-after-servicing, RDP disconnection/reconnection or real DPI screenshot is certified.
- Default Auto Reapply OFF; unknown or ambiguous DLL signatures block patching; backups are mandatory for unattended operations. Cleanup requires explicit user confirmation.

## Historical QA


Version: 0.1.0-preview.10

## Existing verified baseline

- Preview.6 Windows GitHub Actions succeeded: .NET 10 WPF build, synthetic signature and PE-range tests, NSudo 8.2 archive SHA-256 verification, single-file EXE publish, and read-only DLL scan. Run: https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42562651909

## Preview.7 acceptance gates

- The main theme and all five windows must compile and render at 100%, 125%, 150% and 200% scaling; version in titles, icons readable, action buttons not clipped.
- Successful-fix reports must be generated only after Apply returns successfully, and GitHub Issues POST must use a temporary token and a fixed public issue URL. Compatibility workflow validates an allowlisted version-only schema and aggregates into `data/successful-fixes.csv`.
- GitHub CI must build the Windows EXE, run synthetic checks, and verify the exact single-x64-EXE update ZIP and offline update probe.
- The user-triggered updater installs only from an administrator-protected Program Files folder. The helper is a protected copy of the current binary; the replacement is backed up and probed before acknowledging success. Unsigned preview updates are never silent.

## Important work still requiring manual Windows VM validation

- Actual NSudo hook loading against a protected Windows DLL and TermService stop/restart.
- Live patch + restore using the exact machine's DLL version, ownership/ACL and rollback validation.
- A genuine GitHub Issues POST with the user's Issues write token and an observed CSV aggregation job.
- A genuine newer-version EXE install and forced-failure recovery test from protected Program Files.
- Authenticode signature/publisher validation: preview EXE is unsigned, manually approved only.

**Status: Preview / not authorized for broad deployment.**

## Preview.8 additional checks

- Explicit rights mask excludes read-only ACL entries; dangerous write/delete/ownership rights still block a writable install directory.
- An isolated Windows test uses disposable PE-like files to exercise File.Replace backup and automatic rollback when a health probe is rejected.
- WPF windows are created offscreen on STA, no windows are shown, and layout passes are measured at four synthetic viewport factors. This is **not proof of actual 200% desktop rendering**.

## Preview.9 acceptance checks

- Create backup is enabled by default and controls the persistent DLL backup for Automatic/Manual Apply. Disabling it requires an extra confirmation; failed-write in-memory rollback is retained.
- A user-reviewed, opt-in successful-fix report includes original/patched SHA-256 and bounded before/after byte ranges, with Windows, DLL and app versions. It does not include paths, usernames or device identity.
- The compatibility GitHub workflow accepts v1 and v2 reports and validates the CSV migration, hashes, offsets, duplicate aggregation and malicious/extra fields.
- Windows Actions checks default backup state, dialog layout, report serialization and offline updater rollback. Live protected DLL and RDP service modification remains untested.

## Published preview.8 -> preview.9 real-EXE regression

- Dedicated Windows Actions job downloads the actual published preview.8 and preview.9 single-EXE ZIP files; both ZIP files are pinned by SHA-256 to already published GitHub assets.
- It checks real offline version self-probes, the shared PortableExeTransaction success path and versioned previous EXE backup checksum.
- Deliberate failed post-install health probe must return the old EXE with its old SHA-256, retain an existing prior .bak file and set the failure hold. Tampered staged EXEs are rejected before replacement.
- Tests run in disposable local temp directories only. The protected Program Files GUI updater helper, full remote desktop service lifecycle and actual system DLL Apply/Restore are NOT exercised.

## GitHub Actions Node.js 24 migration

- Updated all four workflows to supported Node.js 24 actions: checkout@v7, setup-dotnet@v6, upload-artifact@v7 (where applicable).
- This resolves Node.js 20 deprecation warnings from the earlier checkout@v4 and setup-dotnet@v4 references.
- GitHub-hosted windows-2025/ubuntu-latest runners support these action versions. Self-hosted runners need an up-to-date Actions Runner.
- Offline source validator checks that Node.js 20 action references do not regress; build, artifact upload, release publication and published-EXE rollback tests must pass after migration.
- No change to .NET SDK 10, NSudo, Windows DLL patterns, application version 0.1.0-preview.9 or published release assets.

## Published preview.9 on a REAL system DLL (read-only Windows runner QA)

- Windows-2025 GitHub-hosted runner successfully ran the **published and SHA-256 pinned** preview.9 distribution with `--inspect-file` against its actual `%SystemRoot%\\System32\\termsrv.dll`.
- Verified the report's DLL file version and SHA-256 against independent Windows APIs. Actual file version observed on runner: `10.0.26100.32684 (WinBuild.160101.0800)`.
- Compared original DLL SHA-256, SDDL ACL, TermService service state and the presence of the protected NSudo runtime-cache directory before/after the inspection; **all unchanged**.
- Invalid output extension and missing input DLL were rejected without generating corresponding reports. Published full-distribution ZIP digest verified: `9218ee7db297747efd27eb0b3f664caad4e081e858a81005f6080567ade03177`.
- Verified run: https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42587641056
- **Scope limitation:** Windows Server 2025, non-destructive read-only CLI. This is **not** a Windows 11 desktop test, an actual Apply/Restore, permanent DLL Backup On/Off test, TermService restart test, or live Program Files updater integration test.

## Isolated real-DLL-copy backup and Restore regression

- Source DLL: real Windows runner system DLL copied into a disposable temporary folder; the system DLL, TermService and permissions are never modified.
- A dedicated Windows CI gate exercises `DllBackupStore` shared by the production Apply/Restore path and checks Backup disabled creates no file/directory, Backup enabled stores byte-identical original SHA-256 and idempotent reuse.
- The store refuses version/length mismatch, nested or unrelated paths, corrupted backup contents and unrecognized file names. Existing corrupt backup is never overwritten; Restore list hides invalid entries.
- Restoring a valid backup returns exactly the original bytes. The Windows system DLL is read only; live privileged Apply/Restore remains a manual Windows 11 VM acceptance gate.

## Preview.10 final QA scope

- Real Windows DLL bytes are copied to a temporary test folder; original `System32\termsrv.dll` is read-only. The new backup store is driven by the same production code as GUI Apply and Restore.
- Backup disabled creates no persistent backup. Backup enabled stores an exact SHA-256 original, reuses an existing verified backup, fails closed on damaged originals and validates a restored byte-for-byte copy.
- Restore rejects incorrect version recorded in filename, file-size mismatch, malformed extension/name, path outside storage, nested path and damaged copy. A valid backup appears in Restore list; invalid ones are hidden.
- The protected storage trust check refuses user-writable NTFS ACEs or untrusted owner and accepts an explicitly administrator-controlled test directory.
- Remaining: manual Windows 11 live Apply/Restore and TermService recovery from a VM snapshot, full 200% DPI desktop QA, and operator-approved GitHub Issues report submission.

## Preview.11 offline DLL acceptance

- The application remains Windows x64. Offline PE parsing accepts a selected x86/PE32 or x64/PE32+ `termsrv.dll`; it cannot load NSudo or modify the live system DLL.
- A unique exact match in executable PE code may be saved as a different `termsrv.patched.dll`. Source CRC32/SHA-256 is rechecked and output SHA-256 is verified. Existing targets or original-file overwrite are refused.
- Isolated x86/x64 test fixtures cover CRC32 `123456789 = CBF43926`, version/architecture metadata, SHA-256, duplicate/unknown patterns, stale preview, source preservation and refusal to edit resources/headers.
- An optional public `termsrv-offline/v1` report includes architecture, DLL/app versions, CRC32/SHA-256 and bounded changes. It requires user review and a temporary GitHub token; `data/offline-fixes.csv` is distinct from confirmed system Apply reports.
- Cross-process protected operation lock and read-only JSON DryRun export are included, with synthetic CI checks. Real Windows 11 protected Apply/Restore, RDP service restart, and 200% DPI still require manually controlled VM testing.

## Preview.12 — passive RDPControl-inspired health/session controls

- Independent C# read-only DLL health with explicit operator baseline, SHA-256/version/size comparison and no implicit writes. User-editable baseline never participates in Apply/Restore decisions.
- Native WTS API session inventory (local ID, station, state, account). User identities remain local to the GUI, are not logged, persisted or uploaded, and there are no disconnect/logoff methods.
- Test harness uses a disposable synthetic PE for baseline drift, version change, corrupt JSON, oversized baseline, explicit replacement and no silent repair. Native enumeration is PASS/SKIP depending on WTS availability.
- Offscreen WPF smoke validates the session table and health textbox. Live Windows 11 TermService integration, GUI screenshots at true 200% DPI and live Apply/Restore remain manual acceptance gates.

## Published preview.11 -> preview.12 regression (pinned release ZIPs)

- Windows Actions downloads both **published** update-only ZIP archives, rejects SHA-256 mismatches, and launches the real EXE `--update-probe` for both versions.
- Exercises disposable PortableExeTransaction preview.11 → preview.12 replacement, checked original backup SHA-256, forced failed-probe rollback, retention of a pre-existing .bak and rejection of a modified staged EXE.
- The published preview.12 distribution ZIP is independently SHA-256 pinned and inspected against the runner's actual `termsrv.dll` using the CLI in **read-only** mode. DLL SHA-256, SDDL ACL, TermService state and NSudo cache are compared before and after. These are not live protected Apply/Restore tests.

## Preview.13 — RDP policy and operation-history QA

- Read-only diagnostic compares local and policy registry values without writing keys, refreshing GPO, restarting TermService, changing firewall rules, disconnecting sessions or modifying DLL files.
- Policy values are evidence, **not** proof that Group Policy has refreshed. Firewall inbound rule effectiveness is not inferred. Missing/unreadable/invalid values are not treated as safe defaults.
- Local operation history is a bounded JSONL metadata view; absent/corrupt or oversized history does not authorize any protected write and a read creates no files. Stored records contain no host/account names, local paths, raw exception messages or tokens.
- Synthetic and native Windows read-only checks are covered by `--rdp-policy-history-qa`; offscreen WPF smoke also checks both new grids. GitHub-hosted tests cannot replace interactive RDP/TermService and 200%-DPI manual Windows 11 acceptance.

## Published Preview.12 -> Preview.13 checks (release assets, 2026-11-09)

- Published `v0.1.0-preview.13` is an **unsigned prerelease**, not Stable. The updater-only ZIP is SHA-256 pinned to `504a371266dc45ee99a89538f9833ce994ad96f8764524d1b628ea45b8004ee8`; the full distribution ZIP is pinned to `cb99903ff0033670d6bfdce912a95657cfd2d46e4322d69c3a365e8dea714d1b`.
- [Published EXE upgrade/rollback QA](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42606117672): **PASS** on a disposable Windows 2025 runner: verify both downloaded ZIP digests, launch real Preview.12/Preview.13 EXEs, exercise upgrade, retained EXE backup, health-probe failure/rollback and staged-file tamper refusal.
- [Real Windows termsrv.dll read-only QA](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42606117680): **PASS** using the actual Preview.13 release EXE: inspect a real installed DLL, validate report version/hash, reject invalid paths/extensions, and independently confirm DLL bytes, NTFS ACL, TermService status and NSudo cache remain unchanged.
- Neither workflow applies a DLL patch, changes Windows services or proves interactive Windows 11 RDP functionality. Manual protected Apply/Restore and 200% physical DPI remain open acceptance gates.

## Preview.14 — transactional RDP Settings and service recovery

- Registry and recognized inbound Windows Firewall rule states are snapshotted before any Save writes. Policy conflicts, unsupported registry types and missing/unknown target rules fail closed.
- A sequential transaction verifies each write; on any failure it attempts reverse-order rollback of *every attempted* operation, including a partially successful setter. Incomplete rollback is surfaced as a separate critical error. The GUI refreshes current local values rather than treating attempted checkboxes as confirmed state.
- ServiceGuard preflights TermService and optional RDP services, refuses transitional states, stops only previously running services and makes a best effort to recover even after a partial Stop failure. Failed recovery is reported explicitly.
- Windows CI includes `--rdp-transaction-qa` fault injection and the release workflow requires it. These are **synthetic** operations: no live TermService, Windows Firewall, registry or system DLL is written by these tests.
- Real Windows 11 VM protected Apply/Restore and RDP-session recovery, GPO/firewall effectiveness, and actual 200%-DPI visual review remain unverified acceptance tasks.

## Published Preview.13 -> Preview.14 release-asset QA (2026-11-09)

- Published `v0.1.0-preview.14` is an **unsigned prerelease**, not Stable.
- Independent GitHub Releases SHA-256 digests are pinned: updater-only ZIP = `30e91a533877860b8d4f82f5d694a6dd4849f66c8ad7be613fd88434bbf25632`; full x64 distribution ZIP = `62aff47538d323d40a95aa769215e89a793319d9f938b8238e97298018a159f4`.
- [Published Preview.13 -> Preview.14 EXE replacement/rollback](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42609330936): **PASS** on Windows 2025 in disposable directories with the actual release ZIPs and EXEs. Checks version probe, protected-package SHA-256, backup preservation, replacement, failure-injected health-probe rollback and tampered staged-file refusal.
- [Published Preview.14 real system-DLL read-only inspection](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42609330997): **PASS** on a real Windows 2025 system `termsrv.dll`; verified report data plus original file SHA-256, SDDL ACL, TermService state and native cache unchanged.
- Both are **non-destructive** Windows Server 2025 checks, not Windows 11 live Apply/Restore, user-session or firewall/GPO end-to-end acceptance. Those remain manual VM gates.

## Preview.15 — exact signature evidence and Manual HEX viewer

- Automatic displays each catalog original/replacement pattern, hit count and locations for diagnosis, keeping `Ambiguous` fail-closed and preserving the existing executable-section Apply preflight.
- Manual live lookup allows short/incomplete Find text, compact or space-delimited HEX and one-byte `*`/`??` wildcards. Results are capped at 24; broad or malformed input never generates replacement instructions.
- The read-only HEX viewer displays bounded 16-byte-per-row offset/HEX/ASCII context from **the same DLL snapshot as the selected match**, with fixed-match and wildcard color emphasis, Previous/Next navigation and optional Copy actual HEX. The viewer does not read on startup when no mask is entered.
- Imported Patches.txt catalogs now support one-click read-only inspection of all entries with separate OS and DLL build evidence and exact PE safety checks. Unique candidates are suggestions until a separate operator-selected manual verification; version labels alone never authorize Apply.
- GitHub Issues require account sign-in or a write token. No unauthenticated upload endpoint is deployed; users can copy a reviewed report without sending it.
- `--pattern-inspection-qa` and offscreen WPF control smoke are CI/release gates. **Actual 200%-DPI layout, live RDP sessions, protected Apply/Restore and Windows 11 VM acceptance are not certified here.**

## Published Preview.14 -> Preview.15 release-asset QA (2026-11-09)

- Release: [v0.1.0-preview.15](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v0.1.0-preview.15), **unsigned prerelease**, not Stable.
- [Published upgrade/rollback Windows 2025 QA](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42618817127): **PASS**. Pinned and downloaded real Preview.14/Preview.15 EXE-update ZIPs; tested actual executable replacement, pre-upgrade backup, post-update version probe, injected health-probe rollback, and tamper rejection in disposable directories.
- [Published genuine system DLL read-only QA](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42618817040): **PASS**. Pinned full Preview.15 x64 distribution, ran the released EXE against an installed Windows 2025 `termsrv.dll` and independently verified original DLL SHA-256, SDDL ACL, TermService state and NSudo cache are unchanged. Invalid report extensions and nonexistent DLL paths are rejected.
- Pinned release SHA-256 digests:
  - Full Windows x64 ZIP: `a81007d454fccad0a2285bae43fb5265924bdc19ef95e1c6e6690dd7c8da25b4`.
  - Updater-only EXE ZIP: `2d73cc716358161d8822cbd8c4c0cd7b054d3a994a4006909a5ad24fd99eebcb`.
- The published-asset tests are deliberately **non-destructive Windows Server 2025** jobs. They do not certify live Windows 11 26H2 RDP function, physical 200%-DPI HEX viewer appearance, real protected Apply/Restore or firewall/GPO behavior. Manual Windows 11 GUI acceptance is specified in `docs/WINDOWS_SMOKE_TEST.md`.

## Preview.16 — updater eligibility and manual-install guidance

- Explain the precise `UpdateInstallBridge.CanInstall` blocking reason below the preview release notes, including user privileges, packaged EXE path, Program Files ACL restrictions and live/cached status. **No safety requirement is bypassed**.
- Added Open GitHub release for manual download of the full x64 ZIP. Opening this public link does not submit diagnostic data.
- Corrected the outdated signed-installer text: updates are unsigned, intentionally manual and verified by SHA-256.
- WPF offscreen smoke asserts explicit install-eligibility message, release-link action and initially disabled Install state.
- This is a UX gate only: interactive Windows 11 updates from protected Program Files still require manual VM testing.

## Preview.17 — SHA-bound signature evidence and Automatic → Manual HEX navigation

- **Automatic → Check DLL:** binds its signature and fallback evidence to the preview SHA-256 and independently revalidates the installed DLL before cached results are reused. On mismatch, stale Apply and report-export controls are refused.
- **Inspect selected Find / Replace in HEX:** transfers only the selected existing masked sequence to Manual's read-only viewer, clears Replace and requires a separate operator check before any action.
- **Export signature evidence:** creates a new local `.txt` report with DLL version/hash and bounded exact/near-match results. No anonymous upload and no overwrite. Unsafe imported label metadata is filtered.
- Functional SHA `04c216e1b9ca4c211f512293f117ea5f436557f6` passed CI: 55 signature tests, 91 core assertions and 20 offscreen WPF layouts. Final Preview.17 CI and release must be checked again. No live Windows 11 Apply/Restore or physical 200%-DPI acceptance has been verified.

## Published Preview.16 → Preview.17 release-asset verification (2026-11-09)

- Published [v0.1.0-preview.17](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v0.1.0-preview.17) is an **unsigned prerelease**, not Stable. It preserves the Preview.16 updater eligibility controls.
- [Real published EXE upgrade and rollback](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42625530131): **PASS** on disposable Windows Server 2025 directories. Pinned published Preview.16 and Preview.17 updater ZIP digests, launched real EXEs, checked version and backup, exercised rollback on health-probe failure and rejected a tampered staging file.
- [Published Preview.17 real system DLL read-only inspection](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42625530220): **PASS**. Inspected a genuine Windows Server 2025 `termsrv.dll`, independently confirmed SHA-256, NTFS SDDL, TermService state and NSudo native cache unchanged, and rejected unsafe report extensions/missing DLL paths.
- SHA-256 updater-only ZIP: Preview.16 `f529e337b733d593bfe6ae657c215fe5e4f0c283eef2438e35f06c33591ec477`, Preview.17 `9e34b8b976a7ec9c0200e55f32a506289619372ed5eb4def70cacb69b46a9baf`.
- SHA-256 full Preview.17 x64 ZIP: `a58088407684fe6b0400d2f683f68592af0c60c486a97a98d9c895a0b45402e0`.
- These are **non-destructive Windows Server 2025** checks. They do **not** certify actual Windows 11 26H2 pattern compatibility, protected Apply/Restore, active RDP sessions, Group Policy/firewall effects or physical 200%-DPI GUI rendering.

## Cross-profile ambiguity diagnosis — Windows 11 26H2 evidence

- Operator-provided `termsrv-signature-evidence/v1`: Windows 11 26H2 OS build `26300.9711`, `termsrv.dll` version `10.0.26100.8115`, SHA-256 `e40261e4ee89f4dc9b4a3ea23b53631aac2868d533a3930b92a9c821a2bf9456`.
- Existing generic x64 Find mask matched once at `0x0006D20A` (8 fixed bytes), and the 25H2/26H2 alternate layout matched once at `0x000A6896` (19 fixed bytes). The 24H2 family did not match. **This is two distinct full-profile matches, not a repeated match of one signature.** Neither replacement was present.
- New read-only profile-level classification reports the two candidates, their offsets and fixed-byte counts separately from within-profile repeats/mixed states, and the export does the same without copying arbitrary untrusted profile labels verbatim.
- Regression fixtures reproduce both the operator's reported offsets and the match pattern using **synthetic data**, not the original Windows DLL. No auto-selection or protected DLL modification. The exact source file has not been independently provided for binary/PE semantic analysis; a longer signature is not proof of safe applicability.

## Catalog corrections — Generic JE/JZ and Server 2022 manual pattern

- The Generic automatic Find mask now fixes `0F 84` (JE/JZ), with **three** variable displacement bytes and a fixed final `00` for this catalog variant. Previously the `84` opcode was incorrectly matched as a wildcard, potentially accepting `0F 85` or other branches.
- In the **manual-only legacy catalog**, Windows Server 2022 OS build `20348.3091` has the operator-corrected final byte `00` instead of `20`. This edit is **not** evidence that the actual system DLL has been independently verified; OS build alone cannot certify a patch profile.
- Regression checks reject a different jump opcode or a nonzero final displacement byte. Distinct exact profiles still remain `Ambiguous` until separately validated: narrowing a Find mask never authorizes an unverified protected write.

## OS-aware specific-over-generic automatic patch selection

- On an installed Windows 11 24H2/25H2/26H2 **Client**, a uniquely matching embedded signature tagged for the installed version takes priority over a simultaneously matching older generic fallback, *only* when no other distinct or overlapping target competes. The program builds the preview for the **specific target only**. A single exact Generic match remains eligible for its normal verified path.
- Manual, imported-catalog and offline DLL inspections do not silently inherit host-specific precedence. Unsupported OS versions, untrusted labels, multiple specific candidates, mixed Find/Replace, repeated/overlapping byte matches and all executable-PE validation failures still block Apply.
- Regression tests verify specific-only patch bytes, generic unchanged, already-patched specific detection, unique generic fallback, no host-OS context, untrusted imported catalog and manual refusal. The installed Windows 11 26H2 system DLL was **not modified** by CI; byte selection correctness is not an end-to-end RDP license or functional validation.

## Preview.18 release gate — specific-over-generic automatic selection

- Windows Actions verify synthetic exact matches in the embedded catalog, including the corrected 0F 84 opcode, manual-only Server 2022 trailing 00, and host 26H2 precedence. A matching Generic fallback never produces a second edit when a unique trusted version-specific profile is selected.
- A Ready state is only an inspected preview; Windows 11 live protected Apply/Restore, service lifecycle, real RDP connections, licensing implications and physical 200% DPI remain **outside GitHub-hosted CI**.
- The installed termsrv.dll version 10.0.26100.8115 / SHA-256 e40261e4ee89f4dc9b4a3ea23b53631aac2868d533a3930b92a9c821a2bf9456 was reported by an operator, not independently obtained or modified in the runner. No claim of live compatibility is made.

## Preview.18 Automatic signature comparison / Manual validation

- The Automatic tab now has a selected-group read-only monospaced HEX panel: byte-index header, **Find directly above Replace**, fixed two-digit display width even for catalog wildcard `*` (displayed as `??`), byte counts and exact-match offsets. The full report also preserves aligned pairs and horizontal scrolling; the underlying catalog Find mask is unmodified by its display formatting.
- Current embedded automatic catalog contains three x64 pairs with equal Find/Replace lengths: Generic **12/12** (fixed `0F 84`, 3 wildcard displacement bytes), Windows 11 24H2 **13/13** and Windows 11 25H2/26H2 **19/19**. Matching the pattern length does **not** validate replacement semantics or license compatibility for a particular DLL version.
- The Manual editor validates Find/Replace groups locally and explains missing fields, malformed HEX, wildcard placement and unequal byte counts *before* `Check manual pattern` starts any inspection. Invalid/incomplete editor input is not appended to the protected-operation failure log. Existing historical log records remain unchanged.
- New regression tests inspect all three embedded signatures, aligned two-character cells, wildcard display, read-only evidence formatting and unequal/incomplete Manual input.

## Preview.19 — ordered Automatic signature evidence

- Read-only ranked list presents the version-relevant signature before Generic fallback. Exact Find/Replace counts and offsets, chosen/skipped/blocked reasons, and one-target behavior are visible on the Automatic tab.
- External 12-byte in-memory hotpatch variant is a reference row only, not a fourth trusted disk Apply rule. It may coincide with the trailing 12 bytes of an exact 19-byte Find. On the operator-reported 26H2 fixture (synthetic reproduction only), the 19-byte Find starts at 0x000A6896 and the 12-byte suffix at 0x000A689D.
- On Server 2025 the system file remains inspection-only despite the authentic read-only 13-byte match at 0x0009C43F. No protected Server Apply or live RDP session testing is claimed.

## Preview.20 — anonymous UniversalDiagnostics relay client

- The canonical `UniversalDiagnosticsRelayClient.cs` is vendored from `sgennadi/UniversalDiagnocticsModule`, draft relay branch `feature/universal-anonymous-relay-v1`.
- Exact outgoing JSON must be reviewed before a manual send. The local description and other non-allowlisted fields are excluded; GitHub credentials remain server-only.
- Local pending state changes only after a validated server reply containing the exact event ID, project and GitHub Issue URL.
- Tests use a fake HTTP handler; no real diagnostic is transmitted. **The relay receiver is not yet deployed.** Before configuration, anonymous sending is disabled and local records remain pending.

## Preview.21: session-aware independent Automatic Apply

- Verified design intent: current interactive session is read using WTSClientProtocolType and SM_REMOTESESSION. Console (protocol 0, remote metric false) uses the original privileged Apply path. RDP/ICA or unknown uses a noninteractive one-shot SYSTEM task. Inspect again immediately before Queue and again inside the worker.
- Automatic when Ready opens compact Apply / Check / Advanced / Cancel. No changes on startup. Advanced retains the full feature set and supports ordinary local/console automatic Apply. Manual/Restore are blocked from an RDP GUI until independent executors support them.
- SYSTEM worker stages a protected self-contained executable, verifies EXE/source/expected output SHA-256, validates approved plan and mandatory protected backup, then uses existing transaction and NSudo privileged writes. A task/job identifier is not a patch signature, file path or replacement byte vector.
- Saved status is not considered success until after byte verification and service recovery. Closing GUI does not terminate a running session-0 job. The one-shot task can still be interrupted by shutdown/power loss or OS-level termination.
- Admin-only backup storage moved to `%ProgramData%\\TermsrvPatcherUnified.Secure\\Backups`. Legacy audit-root backups are never automatically trusted or migrated. No ACL bypass or `takeown` fallback.
- **Not yet certified on a disposable Windows 11 VM:** real SYSTEM task creation and execution, service interruption under RDP, physical 200% display and post-Apply reconnection/Restore.
- **Verified non-destructive SYSTEM task:** [Windows CI run 42685718489](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42685718489) successfully scheduled and executed the published Preview.21 EXE under LocalSystem in Session 0 with a protected job directory. This smoke does not inspect, write, or restart the installed system DLL/RDP services.
- Headless `--reapply` is session-aware too: local console / existing SYSTEM Session 0 uses direct Apply; an interactive RDP launch queues the protected job with exit code 6 rather than claiming success.

## Preview.22: protected no-full-backup and source-free Revert

- Compact Apply / Revert / Check / Advanced / Cancel includes opt-in **Do not create backup** (unchecked by default) with a second confirmation; both Advanced Automatic and RDP SYSTEM workers use the operator's selected full-backup policy. A compact SHA-bound DPAPI recovery journal is mandatory for automatic patch transactions even without full backups.
- Optional full original is copied to System32 `termsrv.dll.bak` and the protected ProgramData backup store. The protected DPAPI index binds `.bak` to exact SHA-256, file length and version. A later approved Apply after Windows servicing archives an earlier indexed `.bak` before replacing it with the verified original for the current version; **Check never writes backups**.
- Quick Revert sources: (1) exact matching protected journal; (2) one consistent protected original backup or System32 `.bak` whose SHA-bound replay matches current DLL; (3) ONLY when both are unavailable, independent source-free reversal of unique fully fixed 13/19-byte catalog signatures on the matching Windows 11 family. Generic wildcard/ambiguous/unknown profiles are NOT invertible without original evidence.
- A source-free reconstruction is explicitly not an authenticated Microsoft original: two user confirmations and distinct history semantics. Source/target hash, Windows version and pre/post bytes are checked before the protected write. Local console is direct; RDP/unknown uses one-shot LocalSystem Session 0 Revert worker with durable result status.
- Automated Windows tests exercise synthetic PE copies, known fixed-pattern reversibility, duplicated bytes refusal, unknown-build refusal and compact GUI controls. **No live System32 write, real Windows Update, licensed RDP reconnection or protected system Revert is certified.** Test only on an authorized disposable VM with an independently accessible console.
