# TermsrvPatcherUnified

**Latest Stable:** [`1.0.5`](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.5) (2026-11-11). **Previous Preview:** `1.0.5-preview.5`. Preview and Stable are separate; only versions newer than the installed release can be offered for installation.

**RDP Doctor:** [read-only connectivity diagnosis, Windows events, prioritized evidence and next steps](docs/RDP_DOCTOR.md). In Stable 1.0.5, it is integrated into **Advanced > Remote Desktop**; a single Run RDP Doctor button collects both the summary and expandable technical security evidence.


**RDP security inspections:** [RDP Firewall, local logon rights, TLS certificate and graphics](docs/RDP_SECURITY_INSPECTION.md). **Auto-update settings:** [Auto-update Stable, recurring check, SYSTEM task restrictions and manual EXE approval](docs/AUTO_UPDATE_POLICY.md).


**RDP settings audit:** [local/GPO registry map, inline security editor and future features](docs/RDP_SETTINGS_AUDIT.md).


**Latest Stable release:** [`1.0.5`](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.5) · **Published:** 2026-11-11 · **Platform:** Windows x64, .NET 10 WPF · **Publisher signing:** unsigned

TermsrvPatcherUnified is a Windows Remote Desktop inspection and manually operated `termsrv.dll` maintenance utility. It combines exact signature inspection, manual patterns, separate offline DLL processing, protected backup/Restore, read-only system health, RDP settings and an integrated updater.

**[Releases](https://github.com/sgennadi/TermsrvPatcherUnified/releases)** · **[Version history](CHANGELOG.md)** · **[Test status](docs/QA_STATUS.md)** · **[Security and recovery](SECURITY.md)**

**Google reporting verified:** [direct Google-to-GitHub diagnostics](docs/DIRECT_REPORTING.md) replaced Formspree in Preview.28. A real user-authorized submission from Preview.28 was accepted as [GitHub Issue #32](https://github.com/sgennadi/TermsrvPatcherUnified/issues/32), and its reviewed Windows/DLL metadata appears in [the observations CSV](data/diagnostic-observations.csv) with `verification=unverified`. This proves receipt of that report, **not** that a patch worked or that all deployments will succeed. Sending is opt-in, requires a preview of the exact typed metadata, creates a **public** GitHub Issue only after explicit approval, and requires no end-user token, login, or local file. The former public Formspree ID remains solely in source archive documentation.

## Stable 1.0.5

[Stable 1.0.5](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.5) promotes the tested 1.0.5-preview.5 features. Remote Desktop and RDP Doctor share one Advanced tab; a read-only DLL compatibility index compares observed SHA-256/version evidence without treating user reports as proof that an RDP patch works. Unified Apply reports can be reconstructed after an RDP reconnect and sent via the existing Google Apps Script receiver with explicit review. A partially failed dual delivery retries only missing compatibility evidence and automatically closes after confirmed GitHub receipts. The live report reached [Issue #46](https://github.com/sgennadi/TermsrvPatcherUnified/issues/46) and [Issue #1](https://github.com/sgennadi/TermsrvPatcherUnified/issues/1), populating [successful-fixes.csv](data/successful-fixes.csv).

**Stable update safety:** A selected Preview must be strictly newer than the installed version under SemVer (for example, `1.0.5-preview.5 < 1.0.5`), or Install is rejected. A separate Preview channel and manual approval remain available for intentionally installing genuinely newer pre-releases. Published Preview releases never change the GitHub Latest Stable designation. Updates verify SHA-256, stage a protected copy of the current EXE, back up the original and attempt rollback after failed health checks. No unsigned EXE is installed unattended.

**Auto Reapply:** Silent Windows Update reporting is opt-in, and only verified successful operations may report after prior consent; the live Windows Update/Scheduler path has not yet been tested end to end. Public self-reports do not authorize DLL edits.

## Stable 1.0.4

[Stable 1.0.4](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.4) was published on 2026-11-10. It adds the read-only RDP Doctor with prioritized local network/service/policy findings and bounded Windows RDP event metadata.

**DLL version and retrospective report recovery (1.0.5-preview.4):** Windows DLL resources can display a numeric version followed by `(WinBuild.160101.0800)`; Preview.3 rejected that string during public report validation even though its protected Apply succeeded. Preview.4 retains the full raw version for protected backup/journal matching and exports only the normalized numeric version to the strict Google schema. If a successful Preview.3 one-shot SYSTEM job has no report metadata, Preview.4 can recover the exact changed spans from the machine-protected DPAPI journal after independently checking the immutable job request, original and installed DLL SHA-256, and executable-section bounds. This uses **read-only reconstruction** and never repeats Apply. A prior receipt, incompatible/missing journal, Failed or AlreadyPatched will not create a new report. The original staged EXE is checksum-verified to preserve the actual Preview.3 application version. This remains a **user-reviewed public submission**; no data is sent merely by showing the dialog.

**RDP-session report recovery (1.0.5-preview.3):** one-shot SYSTEM Apply records a bounded, verified report payload next to its protected job status. A reconnected GUI verifies the same approved request and the *current* installed DLL SHA-256 before offering the Unified Apply report once. Simple and Advanced keep a manual Share option if the first offer was dismissed. Old jobs without this evidence, failed jobs, AlreadyPatched, or unattended post-Windows-Update Auto Reapply never create an unverified popup. The ordinary Diagnostics dialog closes immediately after a confirmed GitHub Issue receipt; failed delivery remains visible. No real protected DLL changes are performed by CI.

**Combined Apply report (in development):** a single post-Apply review includes strict Windows/DLL diagnostics and separate compatibility evidence, with one Send confirmation. An optional unchecked-by-default checkbox stores administrator-protected consent for future **silent** reports after newly successful verified Auto Reapply; Simple and Advanced provide a Stop automatic reports control. Failed/skipped/AlreadyPatched operations send nothing. Public GitHub records remain UNVERIFIED.

**Stable 1.0.5 feature:** [DLL compatibility index](docs/DLL_COMPATIBILITY_INDEX.md) compares local DLL version and SHA-256 with bundled anonymous observations and self-reported fix data. All submissions remain UNVERIFIED. The index does not authorize DLL modification.
**1.0.5 reporting:** the completed local-console Apply and offline DLL copy dialogs can now preview/send strict compatibility reports through the already configured Google Apps Script endpoint, without GitHub credentials on the user's PC. With explicit consent, Google posts a public GitHub Issue #1 comment; [compatibility-report.yml](.github/workflows/compatibility-report.yml) collects validated self-reports into [successful-fixes.csv](data/successful-fixes.csv) and separately [offline-fixes.csv](data/offline-fixes.csv). The first upload always requires confirmation; future verified Auto Reapply may report silently only after a separately approved, revocable machine-wide opt-in. **The owner deploys [Code.gs](integrations/google-apps-script/Code.gs) to Google Apps Script independently; live compatibility delivery has now been confirmed.** reports do not authorize Apply or imply working RDP connections.

## Stable 1.0.3

[Stable 1.0.3](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.3) was published on 2026-11-10 after [Windows push CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42893210409), [PR CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42893283992), and the [Stable publishing gate](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42893688563) passed.

Read-only RDP connection inspection covers Windows Firewall rule metadata, LSA Allow/Deny logon rights, the listener TLS certificate and GPU/AVC/WDDM computer policies. The separate machine-wide **Auto-update Stable** checkbox checks GitHub at startup and every four hours while the GUI is open. An enabled protected Auto Reapply task can also perform a read-only daily version check. **No unsigned EXE is installed unattended**; every installation must be approved interactively using the existing verification and rollback workflow.

Preview and Stable channels now strictly filter both GitHub's prerelease flag and SemVer; incorrect cached cross-channel results are ignored. Blank-password status is shown as Restriction ON/OFF without raw numeric suffixes. These checks cannot guarantee external RDP connectivity or full GPO effectiveness.

## Stable 1.0.2

[Stable 1.0.2](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.2) was published as a non-prerelease on 2026-11-10 after [Windows safety CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42882045385) and the [Stable release safety gate](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42882425777) completed successfully. The published x64 portable archive includes exactly `TermsrvPatcherUnified.exe` and `Example.txt`; a one-EXE updater ZIP and SHA-256 file are also available.

This update provides a larger, readable RDP policy table with color-coded and text-labelled edit permissions, per-row Edit buttons and double-clicks; a single inline blank-password security editor; extended read-only GPO diagnostics and a persistent **First Seen (Unverified)** DLL reference. It does not alter automatic patch signatures, authorization to write protected files or Microsoft licensing requirements.

A first-seen DLL observation is **not** verified original DLL provenance. Domain security GPO ownership of LSA settings is not inferred from the RDP policy key. Full-screen visual DPI testing and real Windows 11 RDP reconnection still need user-side verification.

## Stable 1.0.1

[Stable 1.0.1](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.1) was published on 2026-11-10 after [Windows safety CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42874775040) and the [Stable release gate](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42875269490) passed. The release includes a compact source-aware RDP dashboard, a separate System Health tab for DLL integrity and uniform modern confirmation/status dialogs. RDP service, firewall, GPO and connection status are never conflated: unknown and unverified values are labelled explicitly. The unsigned portable ZIP contains only the EXE and Example.txt; the updater ZIP contains one EXE, with a separate SHA-256 file.

This is a UI and usability update. No new automatic signature families or relaxed protected-DLL authorization were added. Physical 200% DPI layout and live Windows 11 RDP reconnection still need hands-on verification.

## Stable 1.0.0

[Stable 1.0.0](https://github.com/sgennadi/TermsrvPatcherUnified/releases/tag/v1.0.0) was published as a **non-prerelease** after [final Windows CI](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42851593054) and the separate [Stable release safety gate](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42851593018) completed successfully. Published assets were verified to contain exactly the portable ZIP, updater-only ZIP and SHA-256 file. These checks are not proof of end-to-end RDP compatibility on every Windows build.

Stable 1.0.0 includes:

- A wider, resizable **Simple** window with its primary actions in a fixed footer, improved **Advanced** layout, and scrollable modern confirmation dialogs; the usable desktop work area is respected at 100–200% scaling.
- **Stable / Preview** selectors inside Updates. The **Updates** buttons in **both** Simple and Advanced show a highlighted **NEW** indicator when either channel has a newer release, with the version and channel in the tooltip. Cached results are explicitly marked and **cannot authorize installation**; Check must verify a live release before Install.
- Read-only identification of an RDP setting's controlling GPO, including the exact RSoP registry value, GPO GUID, and precedence where available. Unknown GPOs are labelled unverified. Approved local DWORD edits are guarded by Group Policy detection, value validation, and rollback; no automatic `gpupdate` or service restart.
- Consent-based Google Apps Script-to-GitHub diagnostic reports, SHA-256 metadata, release ZIP verification, and a portable EXE updater with rollback.
- An explicit non-destructive CI gate for the protected SYSTEM/Session 0 worker, read-only DLL probes, backup integrity, automatic-signature safety, and WPF smoke tests.

**Validation limits:** Windows Server 2025 CI checked read-only/synthetic code paths and non-destructive SYSTEM/Session 0 execution, not a protected live Windows 11 System32 Apply/Revert, actual RDP reconnection, real Windows Update reapplication or on-screen physical 200% DPI rendering. For such operations use an authorized isolated VM and independent local-console recovery. Auto Reapply is OFF by default, and the unsigned EXE requires normal publisher-trust precautions.

## Disclaimer — use entirely at your own risk

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT ANY WARRANTY, TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW.** The authors, maintainers and contributors do not guarantee compatibility, functionality, recovery or availability. To the extent permitted by law, they disclaim liability for service outages, loss of remote access, damaged systems and data loss. Nothing here overrides [GPLv3](LICENSE), excludes liability where prohibited, or grants permission to bypass Microsoft licensing requirements.

**You are responsible** for lawful, licensed use, isolated VM testing, independently verified backups, reviewing proposed changes and keeping local/console recovery access. Modifying Remote Desktop system files can interrupt services or disconnect users; do not rely only on RDP for recovery.

## Features

- **Automatic check:** shows a read-only **Automatic Apply priority list** for the three trusted x64 signature families and a clearly marked 12-byte Hot Patch reference (inspection only). The table displays exact hits, offsets, selected/skipped/blocked decisions and reasons. An OS-aware priority order is displayed; it never applies several profiles in sequence, and the external reference cannot be selected for protected Apply. Compares three embedded x64 signature families against actual DLL bytes. Separate read-only tables show each profile's completeness, fixed-byte count, exact Find/Replace hits and offsets. When an installed Windows 11 version-specific embedded profile and the older generic fallback both match, the single specific target is chosen for the normal verified Apply workflow; the generic bytes are left untouched. Other multi-target ambiguities stay blocked. A unique generic match is still eligible. Manual and offline scans do not infer a host OS. SHA-256, executable-section and rollback checks remain mandatory.
- **Manual patterns:** explicit HEX Find/Replace with `*` or `??` one-byte masks. A live read-only 16-column HEX/ASCII viewer shows the actual installed DLL bytes, highlighted exact/wildcard positions, addresses, context and previous/next matches. Import a pattern catalog and use **Check all imported** to compare every entry against actual bytes and OS/DLL version hints. A near match or a version hint never generates or authorizes replacement bytes.
- **Offline DLL:** choose a `termsrv.dll` in any folder and save a *different* verified output file. Read x86/PE32 or x64/PE32+ architecture, version, CRC32, SHA-256 and byte offsets. x86 files require an exact operator-supplied pattern; the application itself remains x64-only.
- **Protected Apply and Revert / remote-session safety:** the compact startup shows **Apply / Revert / Check / Advanced / Cancel**. A verified Automatic Apply can run locally or as a one-shot SYSTEM Task Scheduler worker in RDP/unknown sessions, independent of GUI disconnect. A compact **Revert** similarly runs at the console or via its own protected SYSTEM worker. The advanced **manual Restore** file picker and **manual Apply** remain console-only. Before writing, workers revalidate the exact current DLL SHA-256, version and approved evidence. The operation remains explicitly confirmed; Task Scheduler Queued is never reported as completed. A real *non-destructive* Windows Server 2025 smoke verified SYSTEM / Session 0 launch but NOT a Windows 11 protected Apply/Revert or actual RDP reconnect. Headless `--reapply` continues to defer RDP Apply with exit code `6`.
- **Full backup optional, recovery journal mandatory for Automatic:** the default is full backup ON: before Apply, verify/create `%SystemRoot%\System32\termsrv.dll.bak` and a separately protected original copy under ProgramData. **Do not create backup** disables both new full copies after an extra warning, but never disables a small DPAPI machine-protected recovery journal containing exact previous byte ranges and before/after SHA-256. During a subsequent *approved Apply*, a stale System32 `.bak` from a previous Windows Update is archived BEFORE being replaced with a verified original for the new DLL; **Check is read-only** and never silently overwrites backups. Corrupt, linked or untrusted backup files fail closed; historic audit-folder backups are not auto-imported.
- **One-click Revert source priority:** exact matching protected journal, otherwise a trusted original backup whose verified reapplication reconstructs the entire current DLL, otherwise a strictly bounded **ExactCatalog** fallback for 13-byte (24H2) or 19-byte (25H2/26H2) **fully fixed** patterns only. Without an original, that last fallback is *byte reconstruction*, NOT proof the DLL is a genuine Microsoft original, and requires two independent confirmations. An unverified, wildcard Generic, unknown, changed or ambiguous DLL has Revert disabled: use Windows component-store repair/SFC, or restore a known-good VM snapshot. Revert cannot recover from arbitrary unrecorded modifications.
- **Remote Desktop (combined):** one dashboard for RDP enablement, NLA, single-session-per-user, eligible Domain/Private firewall rules, local service health, session inventory and read-only Group Policy. The expandable advanced table also inspects TLS/security layer, RDP port, encryption, password prompts, redirection, idle/active/disconnected session limits and TCP/UDP transport. Local setting writes use verification and reverse-order rollback; Group Policy may override them. The local blank-password logon restriction is explicitly separate, OFF is high-risk and needs two confirmations. Monitoring includes DLL hash/version drift against an operator-recorded baseline.
- **RDP post-apply guidance:** after saving settings, the unified RDP dashboard summarizes what changed and recommends a **new connection** or the **next sign-in** where appropriate. **Refresh Computer Policy** is opt-in, explicitly confirmed, and executes `gpupdate.exe /target:computer /force /wait:90` as an administrator; it may reapply non-RDP computer GPOs. It does **not** invoke `/boot`, `/logoff`, stop TermService, or reboot Windows. A locally observed valid listener-port change unlocks **Review service restart**, a read-only warning/instructions dialog; the GUI does not disrupt RDP sessions to perform a restart. A local registry readback is not proof that an RDP client can connect or that the effective domain policy has propagated.
- **Auto reapply after Windows Update — optional, default OFF:** a checkbox in both Simple and Advanced creates a persistent, ACL-protected Task Scheduler job under **SYSTEM / Session 0**, with its own verified EXE under administrator-owned ProgramData (not the potentially writable Desktop EXE). Event ID 19 in WindowsUpdateClient/Operational is checked after a 30-minute delay, plus a post-boot check after 15 minutes and a daily fallback at 03:00. The worker compares the installed DLL SHA-256 with its last observation, skips when a reboot is pending, and attempts Apply **only** with an exact, uniquely verified automatic profile, a supported Windows client and mandatory full backup plus encrypted recovery journal. Unknown/ambiguous/unrecognized DLLs are never patched. Rechecking a previously skipped DLL after an application update is supported. No scheduling is enabled merely by launching or updating the app.
- **Cleanup (explicit opt-in):** choose backup/recovery deletion, local app log/history/diagnostic cleanup and optionally removal of the Auto Reapply scheduled task. The task-removal box is OFF by default and receives a separate Yes/No question. Deleting backups warns about possible permanent loss of Revert; active/uncertain SYSTEM jobs block cleanup. It never erases the installed DLL, Windows Event Logs, Windows Update history, files exported outside app-managed folders, or updater rollback hold.
- **Updates and Diagnostics:** **Updates • NEW** is shown on the Simple and Advanced Updates buttons for a discovered new Stable or Preview release. The updater identifies the channel and available version and allows only a separately approved live-verified Install with backup and rollback. Direct Google Apps Script reporting sends only operator-reviewed typed UniversalDiagnostics v1 evidence to a public GitHub Issue, with a validated receipt; it excludes free-text descriptions, raw logs, paths, hostnames and client GitHub tokens. The optional independent relay is not required for Google delivery. No report is uploaded without explicit consent.
- **Windows DLL telemetry for compatibility observations (opt-in):** in Diagnostics, a checked option collects the running Windows release, Build/UBR, the installed `termsrv.dll` numeric file version and **SHA-256 of the current DLL** without uploading file bytes. The exact values are shown before saving or sending. Uncheck to omit them; a custom DLL digest could identify that custom build. The optional fields travel only in the strictly checked anonymous metadata or reviewed manual report. An approved new Issue can populate `data/diagnostic-observations.csv` as **UNVERIFIED** compatibility evidence, including an error code and app version. This never modifies `Patterns/AutomaticPatterns.txt` or marks a DLL as successfully patched. A live Google-to-GitHub observation was received as Issue #32; no compatibility or Apply success is inferred from that observation.

A unique matching signature does **not** prove Remote Desktop will work after modification or that any additional sessions are licensed.

## Install and inspect

1. Download the x64 package from [Releases](https://github.com/sgennadi/TermsrvPatcherUnified/releases) and verify its separately published `SHA256SUMS.txt`. The portable ZIP contains exactly **TermsrvPatcherUnified.exe** and **Example.txt** (HEX examples plus full GPLv3/MIT license texts and notices); the updater-only ZIP contains **one EXE**. Automatic patterns, NSudo, updater, diagnostics and framework dependencies are compiled/bundled in the EXE.
2. Start the EXE. Choose **Check DLL** for a read-only local inspection.
3. Use **Offline DLL** to inspect a file without modifying Windows services, or use **Remote Desktop** to inspect checksum drift, sessions, security options and policies.
4. For protected Apply or Revert, use an elevated administrator session with independent console recovery access. Keep full backup enabled whenever possible. Turning it off never removes the automatic recovery journal, and exact catalog reconstruction without a genuine original is high-risk.
5. Use **Updates → Check → Install** to update the running portable EXE in place from **any regular local folder**, including Desktop or Downloads. The enabled protected Auto Reapply worker is refreshed only after a successful verified EXE update. Administrator approval is required; the checked release archive and executable must pass hash, architecture and startup health verification. The updater runs separately from an administrator-owned temporary directory, waits for the original EXE to exit and rolls back if its health probe fails. Symlinks, directory junctions and network shares are not automatic update targets. If **Install** is disabled, the updater explains why and offers the official GitHub release ZIP. No silent installation is performed.

6. The Simple window provides one **Auto reapply after Windows Update** checkbox. It is OFF by default; enabling it requires administrator approval and creates the protected scheduled task. Use **Cleanup...** for reviewed deletion of backups or reports, and optionally remove the task via its own unchecked choice and confirmation. Removing backups/recovery journals may make Revert impossible; make an independent system backup first.

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

- Full original backups: `%SystemRoot%\System32\termsrv.dll.bak` (latest verified original) and `%ProgramData%\TermsrvPatcherUnified.Secure\Backups` (protected original copies). Previous System32 `.bak` versions are archived under `%ProgramData%\TermsrvPatcherUnified.Secure\System32Backup\PreviousWindowsVersions`.
- Small authenticated recovery journals: `%ProgramData%\TermsrvPatcherUnified.Secure\Recovery\journal-<patched-sha256>.dpapi`; encrypted/authenticated with Windows DPAPI LocalMachine plus administrator/SYSTEM-only directory ACLs. Key loss may prevent recovery. No client-supplied replacement bytes are accepted during Revert.
- Local operation log: `%ProgramData%\TermsrvPatcherUnified\operations.log`.
- Health baseline: `%LOCALAPPDATA%\TermsrvPatcherUnified\Health\baseline.json`. This user-editable snapshot is **informational only**, never trusted for patch authorization.
- Local WTS session names are not transmitted or included in compatibility reports.
- Optional public GitHub reports are reviewed before sending with a temporary, unsaved token and contain bounded DLL/version/hash/byte-change metadata, **not** usernames, hostnames, IP addresses, full files or raw logs.
- No watchdog or unattended SYSTEM auto-reapply task is created **by default**. The optional protected scheduled task is created only after an administrator explicitly selects and confirms Auto Reapply. Unknown signatures fail closed.

## Requirements and test limits

- Windows 10/11 **x64 client**, .NET 10 Windows Desktop, or a self-contained x64 release ZIP. Windows Server DLLs can be inspected offline; protected system Apply is restricted to supported client systems.
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
