# TermsrvPatcherUnified — 0.1.0-preview.8

This is a **C#/.NET 10 WPF source preview**, integrating features and ideas from:

- https://github.com/geissbuehler/TermsrvPatcher — GPLv3, WPF UI, manual patterns, RDP settings and backups.
- https://github.com/fabianosrc/TermsrvPatcher — MIT, newer Windows DLL signature families.

The automatic catalog adapts the three signature families used by `fabianosrc/TermsrvPatcher.ps1` instead of using the PowerShell script's build-number branching. Full license texts and attribution are included. User-provided legacy patterns live in `Patterns/LegacyUserPatterns.MANUAL.txt` and are **never applied automatically**. Example patterns are excluded from production entirely.

## User workflow

1. **Automatic:** Check DLL. Only a unique byte-level signature produces a `Ready` preview.
2. **Manual:** Paste, save, or import an explicit Find/Replace pattern. `*` matches a single byte in Find; `|` separates multiple pattern groups. HEX tokens must contain exactly two hex digits. Check first, apply only after confirmation. A saved pattern is never added to the automatic catalog.
3. **Search DLL:** Browse any DLL for read-only pattern and structural-marker inspection. If automatic matching fails, candidate offsets and up to ten near-matches (with differing byte indexes) are shown. A near-match is diagnostic only; the program **never invents replacement bytes**. Copy/export the report.
4. **Apply:** Requires an elevated administrator on a supported x64 Windows desktop. Before backing up or touching services, an AMD64 PE DLL validator checks that every proposed edit falls entirely inside an executable PE section. A versioned, checksum-named backup is made first. TermService and dependencies are stopped, NSudo Devil Mode is loaded transiently for a protected write without changing the DLL owner/ACL, the result is verified, and services are restarted.
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

You can also use the included GitHub Actions workflow to build and download a preview ZIP. The workflow runs synthetic pattern matching and PE-boundary tests, publishes a self-contained x64 EXE, and smoke-tests that EXE in **read-only inspection mode**. It does **not** publish a Release or modify any machine's `termsrv.dll` during CI.

## Read-only command-line inspection

From a standard PowerShell session (administrator privileges and a `.ps1` helper are not required for inspection):

```powershell
.\publish\TermsrvPatcherUnified.exe --inspect-file "C:\Windows\System32\termsrv.dll" --report "$env:TEMP\termsrv-inspection.txt"
```

The command saves a text report. It **does not modify** the DLL or remote desktop settings. A successful scan returns exit code 0, and an invalid command or file returns exit code 2. The output filename must end in `.txt`. The read-only command does not request elevation. The interactive GUI requests UAC once; cancelling it leaves protected writes disabled.

## Current limits

- Windows x64 compilation and read-only smoke testing completed in GitHub Actions for preview.5. No actual target `termsrv.dll` patch/rollback or RDP connection testing has been performed. A green CI run for preview.6 is required separately.
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

## Changes in 0.1.0-preview.8

- Prepared a GitHub repository layout, contribution/security policy, issue template and `gh` CLI setup scripts.
- Split read-only CLI execution from elevated GUI mode: read-only inspection no longer needs UAC.
- A matching signature outside executable AMD64 PE sections is blocked **at preview time**, not only when applying.
- Headless `--reapply` now reports non-zero exit codes when it is not elevated or a trusted signature is missing.
- Windows CI additionally performs the offline source/catalog validator before building.
- Built the first local Git commit and a portable `.bundle` for history-preserving import.

The GitHub destination is [sgennadi/TermsrvPatcherUnified](https://github.com/sgennadi/TermsrvPatcherUnified).

## Integrated Updates and Diagnostics (0.1.0-preview.8)

The application **embeds source** from the author's existing shared projects:

- `sgennadi/UniversalUpdater` RC3, `feature/project-audit-rc2`: .NET 10 core, release checking, validated version comparison, source-bound cached state, SHA-256 download/ZIP/PE safety infrastructure. UI: **Updates** in the main toolbar, **Stable/Preview**, **Check** and **Install**, changelog, and visible update indicator. **Install is disabled** until a trusted, signed host installer with rollback is wired; the app does not pretend that downloading an unsigned EXE is installation.
- `sgennadi/UniversalDiagnocticsModule` main: canonical `UniversalDiagnosticsEmbedded.vb` compiled as a companion .NET assembly. UI: **Diagnostics**, explicit review and local capture, copy report and optional direct GitHub Issue submission after reviewing the sanitized report. A temporary, unsaved fine-grained GitHub token with Issues:write is required only for direct publishing; a browser/manual copy route is retained. Nothing uploads automatically, no `.ps1` collector is needed.

Each upstream module remains independently maintained in its original private repository. The source is **vendored into this public application** so Windows GitHub Actions can build without private repository credentials. The embedded diagnostic event schema remains `universal-diagnostics/v1`.

The Windows workflow compiles both module references and app code; the previous preview.5 job succeeded on Windows. The current preview.6 must pass its own workflow before a compiled EXE is claimed. No real system DLL is modified during CI.

## NSudo Devil Mode (0.1.0-preview.8)

The **official NSudo 8.2 stable x64 native DLL** is an opt-in component built **inside** the CI-published single-file EXE. No NSudo installer is required. GitHub Actions stages the official release archive using `scripts/prepare-nsudo.ps1`, verifies its pinned SHA-256, validates the x64 NSudo DLL identity and embeds it as a private resource. On explicit administrator-approved Apply/Restore, the app extracts it to an administrator-restricted folder, verifies the embedded SHA-256 and DLL architecture, loads it only around the protected write, and unloads it. It is never used while checking releases, inspecting binaries or collecting diagnostics.

The previous `takeown.exe` / `icacls.exe` fallback was **removed**: unknown or missing NSudo resources fail closed without changing file permissions. Builds that lack the optional library can still inspect DLLs but cannot apply or restore. `About / Components` shows whether native support is bundled.

Prepare manually on Windows with PowerShell 7: `pwsh ./scripts/prepare-nsudo.ps1`, then `dotnet publish ... -p:RequireNSudo=true`. The CI workflow performs this automatically. No automatic privilege escalation, blank-password RDP or automatic DLL modification is introduced.


## Changes in 0.1.0-preview.8

- Diagnostics can now submit a **reviewed** `universal-diagnostics/v1` report directly to a fixed GitHub Issue endpoint. The token is supplied per submission and cleared from the UI; it is never saved, logged, copied into the report, or sent to any redirect. A public-repository warning and second confirmation are mandatory. Manual copy/open Issue remains available.
- A successful GitHub response is validated against this repository's issue URL and recorded locally in the diagnostic queue. Failures or ambiguous responses are never retried automatically. Mocked GitHub response tests require no network or credentials.
- NSudo extraction uses a separate protected native-code directory rather than the ordinary audit/log folder, avoiding a conflict with inherited ACLs.
- This preview still has no trusted self-install updater and no real-system-DLL patch test. **Install stays disabled** until signer verification and rollback are implemented.

## Changes in 0.1.0-preview.8

- New unified light-blue WPF theme, rounded controls, Segoe MDL2 button icons, app ICO in all windows, adaptive main toolbar, and preview version in every window title.
- Manual **Check / Install** updater: download the separate single-EXE GitHub Release asset, validate GitHub SHA-256/ZIP/x64 PE, and use a protected, current-EXE update helper to replace the app after exit. Previous EXE is backed up; replacement is probed and rolled back on failure. Unsigned previews require explicit confirmation; no automatic install. Available only when installed in an administrator-protected Program Files subdirectory.
- Successful *GUI Apply* offers an optional version-only compatibility submission through a temporary GitHub Issues token. A GitHub workflow aggregates accepted reports to `data/successful-fixes.csv` with Windows name/release/build/UBR, fixed file name (`termsrv.dll`), DLL and application versions, and manual/automatic mode. This is self-reported telemetry, not proof of system compatibility. No hostname, username, IP, file path, DLL bytes, or raw logs are sent.
- GitHub CI now checks the updater ZIP structure, CLI health probe, diagnostics tests and the compatibility CSV aggregation tests. Release publication remains prerelease-only. Live system DLL modification, service recovery, and end-to-end updater rollback require operator-supervised isolated Windows VM acceptance tests.

## Preview.8 verification changes

- The installed EXE updater's Program Files ACL guard now tests only **mutating permissions**; normal Users/ReadAndExecute permissions no longer falsely disable the Install button.
- Windows Actions execute disposable-file `File.Replace` success/backup and forced health-probe rollback tests. No Windows system DLL or RDP service is touched.
- A separate STA offscreen WPF smoke constructs all five windows, checks titles and application icons, and measures their layouts at four synthetic scale factors (100%, 125%, 150%, 200%). These are not actual high-DPI screenshots, and visual clipping still needs a Windows desktop QA pass.
- The updater still requires explicit confirmation and a protected Program Files install location. Preview EXEs remain unsigned and are not auto-installed.
