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
