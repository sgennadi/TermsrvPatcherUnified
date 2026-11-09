# TermsrvPatcherUnified

**Current source version:** `0.1.0-preview.17` · **Status:** unsigned Preview, not Stable · **Platform:** Windows x64, .NET 10 WPF

TermsrvPatcherUnified is a Windows Remote Desktop inspection and manually operated `termsrv.dll` maintenance utility. It combines exact signature inspection, manual patterns, separate offline DLL processing, protected backup/Restore, read-only system health, RDP settings and an integrated updater.

**[Download a Preview](https://github.com/sgennadi/TermsrvPatcherUnified/releases)** · **[Version history](CHANGELOG.md)** · **[Test status](docs/QA_STATUS.md)**

## Disclaimer — use entirely at your own risk

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT ANY WARRANTY, TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW.** The authors, maintainers and contributors do not guarantee compatibility, functionality, recovery or availability. To the extent permitted by law, they disclaim liability for service outages, loss of remote access, damaged systems and data loss. Nothing here overrides [GPLv3](LICENSE), excludes liability where prohibited, or grants permission to bypass Microsoft licensing requirements.

**You are responsible** for lawful, licensed use, isolated VM testing, independently verified backups, reviewing proposed changes and keeping local/console recovery access. Modifying Remote Desktop system files can interrupt services or disconnect users; do not rely only on RDP for recovery.

## Features

- **Automatic check:** compares three embedded x64 signature families against actual DLL bytes. Separate read-only tables show each profile's completeness, fixed-byte count, exact Find/Replace hits and offsets. When an installed Windows 11 version-specific embedded profile and the older generic fallback both match, the single specific target is chosen for the normal verified Apply workflow; the generic bytes are left untouched. Other multi-target ambiguities stay blocked. A unique generic match is still eligible. Manual and offline scans do not infer a host OS. SHA-256, executable-section and rollback checks remain mandatory.
- **Manual patterns:** explicit HEX Find/Replace with `*` or `??` one-byte masks. A live read-only 16-column HEX/ASCII viewer shows the actual installed DLL bytes, highlighted exact/wildcard positions, addresses, context and previous/next matches. Import a pattern catalog and use **Check all imported** to compare every entry against actual bytes and OS/DLL version hints. A near match or a version hint never generates or authorizes replacement bytes.
- **Offline DLL:** choose a `termsrv.dll` in any folder and save a *different* verified output file. Read x86/PE32 or x64/PE32+ architecture, version, CRC32, SHA-256 and byte offsets. x86 files require an exact operator-supplied pattern; the application itself remains x64-only.
- **Protected Apply/Restore:** explicit administrator approval, default-on persistent backup, version/hash/NTFS checks, cross-process lock and an attempted in-operation rollback. Disabling persistent backup requires extra confirmation.
- **RDP Settings:** inspect or configure RDP enablement, NLA, single-session-per-user and eligible Domain/Private firewall rules. Before changes, block conflicting policy values and snapshot affected settings; verify writes and attempt reverse-order rollback if any step fails. A Group Policy refresh may still override local settings.
- **RDP Health:** on-demand local DLL hash/version comparison against an operator-recorded baseline, plus local read-only RDP session inventory via Windows WTS APIs.
- **Updates and Diagnostics:** visible update indicator, manual Check/Install of verified preview packages with EXE rollback, and optional reviewed diagnostics/compatibility reporting. Reports are never uploaded without consent.

A unique matching signature does **not** prove Remote Desktop will work after modification or that any additional sessions are licensed.

## Install and inspect

1. Download the x64 package from [Releases](https://github.com/sgennadi/TermsrvPatcherUnified/releases) and verify its `SHA256SUMS.txt`.
2. Start the EXE. Choose **Check DLL** for a read-only local inspection.
3. Use **Offline DLL** to inspect a file without modifying Windows services, or use **RDP Health** to inspect checksum drift and sessions.
4. For protected Apply/Restore, use an elevated administrator session with console recovery access. Confirm the pattern and retain a backup.
5. Use **Updates → Check → Install** for a manual EXE update only when the current app is running elevated from an administrator-protected Program Files folder. If **Install** is disabled, the updater explains why and provides **Open GitHub release** to download the full ZIP. An extracted EXE launched from Desktop/Downloads is not eligible for in-place update. No silent installation is performed.

Non-elevated, offline-only GUI startup:

```powershell
.\TermsrvPatcherUnified.exe --offline
```

Read-only command-line DLL inspection (no administrator rights required):

```powershell
.\TermsrvPatcherUnified.exe --inspect-file "C:\Windows\System32\termsrv.dll" --report "$env:TEMP\termsrv-inspection.txt"
```

The inspection command produces a `.txt` report; it does not modify the DLL or Windows services. Valid inspection returns exit status 0; invalid input or command returns 2.

## Files, privacy and safety

- Backups: `%ProgramData%\TermsrvPatcherUnified\Backups` (trusted NTFS storage; Restore validates each file).
- Local operation log: `%ProgramData%\TermsrvPatcherUnified\operations.log`.
- Health baseline: `%LOCALAPPDATA%\TermsrvPatcherUnified\Health\baseline.json`. This user-editable snapshot is **informational only**, never trusted for patch authorization.
- Local WTS session names are not transmitted or included in compatibility reports.
- Optional public GitHub reports are reviewed before sending with a temporary, unsaved token and contain bounded DLL/version/hash/byte-change metadata, **not** usernames, hostnames, IP addresses, full files or raw logs.
- No watchdog or scheduled SYSTEM auto-repatch task is created. Unknown signatures fail closed.

## Requirements and test limits

- Windows 10/11 **x64 client**, .NET 10 Windows Desktop, or a self-contained x64 Preview ZIP. Windows Server DLLs can be inspected offline; protected system Apply is restricted to supported client systems.
- The bundled NSudo 8.2 x64 native dependency is verified by SHA-256 and used only for explicitly confirmed protected writes. No `takeown.exe` or `icacls.exe` ownership/ACL fallback.
- GitHub Actions covers synthetic signature/PE safety, offline x86/x64 copy-patching, read-only real Windows DLL inspection, backup-copy integrity, updater rollback and synthetic WPF layout checks.
- **Live system DLL Apply/Restore, RDP service recovery, actual RDP logons and on-screen 200%-DPI layout are not validated by CI.** Test these in an isolated Windows VM with console access.

## Build from source

```powershell
dotnet restore .\TermsrvPatcher.Unified.csproj
dotnet run --project .\Tests\TermsrvPatcher.Tests.csproj -c Release
dotnet publish .\TermsrvPatcher.Unified.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\publish
```

For local NSudo-enabled builds, prepare the pinned official binary with `scripts/prepare-nsudo.ps1` and publish with `-p:RequireNSudo=true`. GitHub Actions does this automatically.

## Documentation and licenses

See [CHANGELOG.md](CHANGELOG.md) for the complete build-by-build history, [docs/QA_STATUS.md](docs/QA_STATUS.md) for test evidence, [docs/RDPCONTROL_SOURCE_COMPARISON.md](docs/RDPCONTROL_SOURCE_COMPARISON.md) for source-level comparisons, and [SECURITY.md](SECURITY.md) for security and recovery guidance.

The application is **GPLv3**. It incorporates ideas from [geissbuehler/TermsrvPatcher](https://github.com/geissbuehler/TermsrvPatcher) (GPLv3) and [fabianosrc/TermsrvPatcher](https://github.com/fabianosrc/TermsrvPatcher) (MIT), with attribution in [NOTICE.md](NOTICE.md) and `licenses/`. The separate RDPControl review does not copy its code.
