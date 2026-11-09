# Preview QA status — 2026-11-09

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
