# TermsrvPatcherUnified — 0.1.0-preview.10

This is a **C#/.NET 10 WPF source preview**, integrating features and ideas from:

- https://github.com/geissbuehler/TermsrvPatcher — GPLv3, WPF UI, manual patterns, RDP settings and backups.
- https://github.com/fabianosrc/TermsrvPatcher — MIT, newer Windows DLL signature families.

The automatic catalog adapts the three signature families used by `fabianosrc/TermsrvPatcher.ps1` instead of using the PowerShell script's build-number branching. Full license texts and attribution are included. User-provided legacy patterns live in `Patterns/LegacyUserPatterns.MANUAL.txt` and are **never applied automatically**. Example patterns are excluded from production entirely.

## User workflow

1. **Automatic:** Check DLL. Only a unique byte-level signature produces a `Ready` preview.
2. **Manual:** Paste, save, or import an explicit Find/Replace pattern. `*` matches a single byte in Find; `|` separates multiple pattern groups. HEX tokens must contain exactly two hex digits. Check first, apply only after confirmation. A saved pattern is never added to the automatic catalog.
3. **Search DLL:** Browse any DLL for read-only pattern and structural-marker inspection. If automatic matching fails, candidate offsets and up to ten near-matches (with differing byte indexes) are shown. A near-match is diagnostic only; the program **never invents replacement bytes**. Copy/export the report.
4. **Apply:** Requires an elevated administrator on a supported x64 Windows desktop. Before backing up or touching services, an AMD64 PE DLL validator checks that every proposed edit falls entirely inside an executable PE section. A versioned checksum-named backup is saved by default; the user may disable persistent backup creation with the Create backup checkbox and an extra explicit warning. TermService and dependencies are stopped, NSudo Devil Mode is loaded transiently for a protected write without changing the DLL owner/ACL, the result is verified, and services are restarted.
5. **Restore:** Select a backup from `%ProgramData%\TermsrvPatcherUnified\Backups`. Its version must match the currently installed DLL.
6. **RDP Settings:** Read or configure RDP, NLA, single session per user and Domain/Private firewall group rules. Does not offer blank-password logons.

UI remembers its last position/size, is Per-Monitor V2 DPI-aware, and uses flexible WPF layout instead of absolute positioning. No PowerShell `.ps1` script is required or launched by the application.

## Requirements and safety

- .NET 10 Windows Desktop; self-contained `win-x64` packaging is available through the workflow.
- Designed for x64 Windows 10/11 client. Windows Server DLLs can be inspected offline but are not modified by this preview.
- **NOT tested against real Windows system DLLs or interactive RDP sessions.** Build and signature tests are provided but cannot certify a binary modification on a target Windows build.
- Changing Windows Remote Desktop files may violate Microsoft license terms or conflict with Windows security/integrity protections. Use only where permitted, after testing on a disposable VM, and arrange console/local recovery access.
- Applying or restoring stops RDP services and can disconnect remote users; services may not restart if Windows is in an error state.
- The application deliberately refuses ambiguous or missing signatures. Windows version strings alone are never treated as proof of a valid patch.
- The optional `--reapply` headless argument is included for advanced use, but **no SYSTEM task is installed automatically**. If you create one, install the EXE in a folder writable only by administrators. Never execute a user-writable script or EXE as SYSTEM.
- Operations log: `%ProgramData%\TermsrvPatcherUnified\operations.log` (local only; not uploaded to GitHub).

## Build on Windows

```powershell
dotnet restore .\TermsrvPatcher.Unified.csproj
dotnet run --project .\Tests\TermsrvPatcher.Tests.csproj -c Release
dotnet publish .\TermsrvPatcher.Unified.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\publish
```

You can also use the included GitHub Actions workflow to build and download a preview ZIP. The workflow checks PE safety, updater rollback, and read-only inspection; a separate main-branch job publishes explicit unsigned Preview Releases. No workflow modifies a real Windows `termsrv.dll` or RDP service.

## Read-only command-line inspection

From a standard PowerShell session (administrator privileges and a `.ps1` helper are not required for inspection):

```powershell
.\publish\TermsrvPatcherUnified.exe --inspect-file "C:\Windows\System32\termsrv.dll" --report "$env:TEMP\termsrv-inspection.txt"
```

The command saves a text report. It **does not modify** the DLL or remote desktop settings. A successful scan returns exit code 0, and an invalid command or file returns exit code 2. The output filename must end in `.txt`. The read-only command does not request elevation. The interactive GUI requests UAC once; cancelling it leaves protected writes disabled.

## Current limits

- Windows x64 compilation, read-only inspection, synthetic update transactions and offscreen WPF checks are covered by CI. Actual protected DLL modifications, recovery and RDP connections are not validated there.
- Firmware, OS or Windows Update changes can invalidate known signatures at any time.
- The read-only scanner searches byte anchors and ranks nearby signatures; it is not a disassembler, proof of compatibility, or formal patch-generator.
- Automatic signatures may require updating after future Windows DLL changes.
- Client-mode apply requires elevated rights and access to the protected DLL; Windows security may block writes.

## Licensing

The combined source is released under **GPLv3**. Contributions include adapted signatures from the MIT-licensed fabianosrc project (see `licenses/fabianosrc-MIT.txt`). The upstream project also credits Rene Nyffenegger's `patch-termsrv.dll` project. Respect both original copyright notices when redistributing.

## Changes in 0.1.0-preview.2

- Enforced exact two-character HEX tokens and stricter manual validation.
- Added read-only closest-signature display when automatic matching fails; no speculative patching.
- Added file save and scan report copy buttons.
- Added PE/AMD64/executable-section preflight to protect against false-positive matches in resources or overlays.
- Added `--inspect-file ... --report ...` for unattended **read-only** checks.
- Added synthetic tests for all automatic signature families, ambiguous/multi-group patterns, near matches and PE boundaries.
- CI includes a packaged-EXE read-only smoke test; it still must be run on GitHub/Windows.

## Previous repository/safety milestones

- Prepared a GitHub repository layout, contribution/security policy, issue template and `gh` CLI setup scripts.
- Split read-only CLI execution from elevated GUI mode: read-only inspection no longer needs UAC.
- A matching signature outside executable AMD64 PE sections is blocked **at preview time**, not only when applying.
- Headless `--reapply` now reports non-zero exit codes when it is not elevated or a trusted signature is missing.
- Windows CI additionally performs the offline source/catalog validator before building.
- Built the first local Git commit and a portable `.bundle` for history-preserving import.

The GitHub destination is [sgennadi/TermsrvPatcherUnified](https://github.com/sgennadi/TermsrvPatcherUnified).

## Integrated Updates and Diagnostics

The application **embeds source** from the author's existing shared projects:

- `sgennadi/UniversalUpdater` RC3, `feature/project-audit-rc2`: .NET 10 core, release checking, validated version comparison, source-bound cached state, SHA-256 download/ZIP/PE safety infrastructure. UI: **Updates** in the main toolbar, **Stable/Preview**, **Check** and **Install**, changelog, and visible update indicator. **Install** can be manually approved from a protected Program Files directory, with SHA-256 validation, EXE backup, health probe and rollback; unsigned previews are never installed silently.
- `sgennadi/UniversalDiagnocticsModule` main: canonical `UniversalDiagnosticsEmbedded.vb` compiled as a companion .NET assembly. UI: **Diagnostics**, explicit review and local capture, copy report and optional direct GitHub Issue submission after reviewing the sanitized report. A temporary, unsaved fine-grained GitHub token with Issues:write is required only for direct publishing; a browser/manual copy route is retained. Nothing uploads automatically, no `.ps1` collector is needed.

Each upstream module remains independently maintained in its original private repository. The source is **vendored into this public application** so Windows GitHub Actions can build without private repository credentials. The embedded diagnostic event schema remains `universal-diagnostics/v1`.

The Windows workflow builds both shared modules and the WPF host. GitHub Actions does not modify a real system DLL.

## NSudo Devil Mode

The **official NSudo 8.2 stable x64 native DLL** is an opt-in component built **inside** the CI-published single-file EXE. No NSudo installer is required. GitHub Actions stages the official release archive using `scripts/prepare-nsudo.ps1`, verifies its pinned SHA-256, validates the x64 NSudo DLL identity and embeds it as a private resource. On explicit administrator-approved Apply/Restore, the app extracts it to an administrator-restricted folder, verifies the embedded SHA-256 and DLL architecture, loads it only around the protected write, and unloads it. It is never used while checking releases, inspecting binaries or collecting diagnostics.

The previous `takeown.exe` / `icacls.exe` fallback was **removed**: unknown or missing NSudo resources fail closed without changing file permissions. Builds that lack the optional library can still inspect DLLs but cannot apply or restore. `About / Components` shows whether native support is bundled.

Prepare manually on Windows with PowerShell 7: `pwsh ./scripts/prepare-nsudo.ps1`, then `dotnet publish ... -p:RequireNSudo=true`. The CI workflow performs this automatically. No automatic privilege escalation, blank-password RDP or automatic DLL modification is introduced.


## Diagnostics and protected native-cache milestone

- Diagnostics can now submit a **reviewed** `universal-diagnostics/v1` report directly to a fixed GitHub Issue endpoint. The token is supplied per submission and cleared from the UI; it is never saved, logged, copied into the report, or sent to any redirect. A public-repository warning and second confirmation are mandatory. Manual copy/open Issue remains available.
- A successful GitHub response is validated against this repository's issue URL and recorded locally in the diagnostic queue. Failures or ambiguous responses are never retried automatically. Mocked GitHub response tests require no network or credentials.
- NSudo extraction uses a separate protected native-code directory rather than the ordinary audit/log folder, avoiding a conflict with inherited ACLs.
- This was an earlier milestone; manual EXE replacement was added later, but live DLL patching still has not been verified in a disposable Windows VM.

## Previous UI and updater milestone

- New unified light-blue WPF theme, rounded controls, Segoe MDL2 button icons, app ICO in all windows, adaptive main toolbar, and preview version in every window title.
- Manual **Check / Install** updater: download the separate single-EXE GitHub Release asset, validate GitHub SHA-256/ZIP/x64 PE, and use a protected, current-EXE update helper to replace the app after exit. Previous EXE is backed up; replacement is probed and rolled back on failure. Unsigned previews require explicit confirmation; no automatic install. Available only when installed in an administrator-protected Program Files subdirectory.
- Successful *GUI Apply* offers an opt-in public GitHub compatibility report through a temporary GitHub Issues token. A GitHub workflow aggregates accepted reports to `data/successful-fixes.csv` with Windows name/release/build/UBR, fixed file name (`termsrv.dll`), DLL and application versions, and manual/automatic mode. This is self-reported telemetry, not proof of system compatibility. No hostname, username, IP, file path, full DLL or raw log is sent.
- GitHub CI now checks the updater ZIP structure, CLI health probe, diagnostics tests and the compatibility CSV aggregation tests. Release publication remains prerelease-only. Live system DLL modification, service recovery, and end-to-end updater rollback require operator-supervised isolated Windows VM acceptance tests.

## Preview.8 verification changes

- The installed EXE updater's Program Files ACL guard now tests only **mutating permissions**; normal Users/ReadAndExecute permissions no longer falsely disable the Install button.
- Windows Actions execute disposable-file `File.Replace` success/backup and forced health-probe rollback tests. No Windows system DLL or RDP service is touched.
- A separate STA offscreen WPF smoke constructs all five windows, checks titles and application icons, and measures their layouts at four synthetic scale factors (100%, 125%, 150%, 200%). These are not actual high-DPI screenshots, and visual clipping still needs a Windows desktop QA pass.
- The updater still requires explicit confirmation and a protected Program Files install location. Preview EXEs remain unsigned and are not auto-installed.

## Preview.9: optional DLL backup and detailed compatibility reporting

- **Create backup before applying** is checked by default on the main window. This controls persistent original-DLL backups for both manual and automatic Apply. If unchecked, the app requests another confirmation; a failed write still attempts rollback to its in-memory original bytes. The EXE updater's backup is separate and unaffected.
- **Restore backup** continues to check the backup file SHA-256 and installed DLL version. It cannot restore an original DLL later if no valid backup exists.
- **Successful-fix v2 reports** now include original SHA-256, patched SHA-256, and exact offset/before/after byte ranges, in addition to the existing Windows/DLL/app version metadata. Reports appear for review only after successful Apply.
- **Privacy:** the report is PUBLIC if the operator supplies a temporary GitHub Issues-write token and clicks Send. No token is embedded or retained. Users can Skip; there is no automatic upload.
- GitHub aggregation accepts both legacy v1 and new v2 report schemas. Source-format and synthetic Windows tests enforce strict validation and migration to the expanded CSV format.
- This release remains **Preview**, not a statement of licensing entitlement or proof of successful live-system DLL modification.

## Preview.10 — protected backup and Restore verification

- Backup On/Off now uses a shared integrity-checked backup store. With Backup disabled, no new persistent backup file or directory is created. An existing, matching SHA-256 backup is reused rather than overwritten.
- Restore verifies the canonical checksum-named backup, the version recorded when it was created, the exact SHA-256, matching file length and 64-bit PE structure. The Restore dialog excludes corrupted, misplaced, malformed or mismatched entries.
- **Important bug fix:** Windows may use MUI satellite resources for FileVersionInfo on a system DLL. A renamed DLL backup may report a different version despite containing identical bytes. Restoring now uses the original version recorded in the backup name plus SHA-256 validation, instead of rejecting a valid backup solely because of MUI lookup.
- Backups must be in a directory controlled by an elevated administrator, Administrators, SYSTEM or TrustedInstaller. Both the application state root and its Backups subdirectory are checked for NTFS owner and mutating ACEs; user-writable directories and reparse points fail closed. The app never silently rewrites unsafe ACLs.
- CI tests work on a throwaway copy of a REAL Windows DLL: checks creation, Backup disabled, no-overwrite, corruption, mismatch, path traversal, verified restoration and accepted/denied NTFS permissions. These **do not** modify live Windows DLLs or restart TermService.
- Release remains unsigned Preview; manual Windows 11 VM validation of actual protected Apply/Restore and 200% DPI is still required.


## RDPControl upstream comparison

See [RDPControl source comparison and prioritized adoption plan](docs/RDPCONTROL_SOURCE_COMPARISON.md). The review identifies independent improvements we can implement in C# while preserving our strict PE checks, protected Backup/Restore path and operator approval. No upstream code was copied and no runtime dependencies were added.
