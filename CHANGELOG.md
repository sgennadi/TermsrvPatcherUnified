# Changelog

## 0.1.0-preview.14 — 2026-11-09

- RDP Settings now stages original registry values and supported inbound firewall-rule states before writing anything. Conflicting Group Policy values or unexpected registry data fail closed.
- Apply/verify each requested change as a reversible transaction. If any write or readback fails, reverse all attempted mutations, including a setter that failed after writing, and explicitly report incomplete rollback when needed.
- Run RDP Settings from a controlled asynchronous task; reload the actual registry settings following success or failure so the UI does not imply unverified changes succeeded.
- Strengthened TermService/SessionEnv/UmRdpService lifecycle: preflight all service states before any stop, reject transitional states, restore only originally running services, and preserve both stop and failed-restart errors.
- New fault-injection suite exercises registry/firewall-style transaction failures and service stop/start recovery without modifying live Windows services, protected DLL files or firewall rules.
- Windows 11 VM acceptance for real system DLL Apply/Restore, service recovery, firewall policy and true 200% desktop DPI remains outstanding. This is an **unsigned Preview**, not Stable.


## 0.1.0-preview.13 — 2026-11-09

- Refocused README on current features and installation; per-build details remain here.
- Added read-only local RDP/Group Policy comparison: RDP enablement, NLA, one-session policy, TCP port, RDP security layer, encryption level and TermService status. Differing or invalid values show warnings; effective firewall rules and actual GPO application are not assumed.
- Added a bounded, user-local operation-history JSONL log and History tab. Records verified Apply, Restore, RDP settings, offline copy and DLL baseline events. History stores UTC, result, app version, optional validated DLL version/hash and failure type, never usernames, hostnames, full paths or exception messages.
- Added synthetic and Windows read-only policy/history regressions with WPF control smoke checks.
- No automatic patching or background registry/service changes. Real protected DLL Apply/Restore and live Windows 11/200%-DPI acceptance remain manual gates.


## 0.1.0-preview.12 — 2026-11-09

- Added passive DLL Health comparison with a manually saved, user-local JSON baseline; reports unchanged, changed bytes, changed version and invalid reference distinctly.
- Added read-only Windows WTS session viewer inside RDP Health tab. No localized qwinsta parsing, disconnect/logoff, silent uploads or automatic re-patching.
- Added synthetic Windows tests for DLL drift, corrupt baselines, no implicit writes, state mappings and native WTS smoke when available; offscreen WPF controls validated.
- All baseline data is informational and never feeds Apply/Restore authorization; full Windows 11 VM functional validation remains open.

## 0.1.0-preview.11 — 2026-11-09

- Added independent Offline DLL tab to select an arbitrary folder's `termsrv.dll`, detect x86/PE32 or x64/PE32+ and save an independent modified DLL file, never overwriting the original or touching Windows services.
- Added original/output CRC32 and SHA-256, DLL version, architecture, edit offsets and before/after bytes; optional user-reviewed public GitHub report stored separately in `data/offline-fixes.csv`.
- x86 DLLs require an exact manual signature until independently validated automatic x86 patterns exist; **no x86 program or system patcher is added**.
- Added administrator-protected cross-process operation mutex for Apply/Restore/RDP Settings, and read-only DryRun JSON export.
- Added README liability and user-risk notice, consistent with GPLv3 and applicable law.
- Extended Windows CI with synthetic x86/x64 PE file tests, source integrity/no-overwrite, signature rejection and checksum validation.
- Real protected DLL Apply/Restore and actual Windows 11 RDP connections remain manual VM acceptance gates; unsigned Preview only.


## 0.1.0-preview.10 — 2026-11-09

- Refactored the persistent DLL backup/Restore path into a shared, independently tested validator.
- Fixed potential refusal of a valid backup when Windows MUI resources change FileVersionInfo results after DLL renaming.
- Added version and SHA-256 checks, exact-length validation, PE x64 structure checks, direct-child directory restriction, and rejection of corrupted or wrongly named backup files.
- Added administrator-controlled NTFS ACL gate and filesystem-link refusal for protected backup operations. Unsafe legacy locations are blocked rather than silently modified.
- Added Windows CI regression using a temporary copy of a real system DLL: Backup On/Off, idempotence, SHA-256 restore, corruption, path mistakes and NTFS ACL trust.
- No live system-DLL modification/TermService integration test has been completed. The version remains an unsigned Preview.

## 0.1.0-preview.9 — 2026-11-09

- Added default-on Create backup checkbox for both automatic and manual Apply, with extra confirmation when disabled; failed-write rollback remains active even without persistent backup.
- Added opt-in successful-fix report v2 with original and patched SHA-256 plus bounded byte offsets and exact before/after data.
- Added v1/v2 compatibility comment parser, strict data validation, CSV migration and negative regression tests.
- Enlarged report dialog, added backup-control UI smoke test and synchronized version numbers and documentation.
- No live Windows system-DLL or TermService modification has been validated. Release remains unsigned Preview.

## 0.1.0-preview.8 — 2026-11-09

- Fixed an overbroad filesystem ACL rights mask that included read access and could disable safe installation from Program Files.
- Added a disposable EXE transaction test for replacement, `.bak` retention, forced probe failure, rollback and failure hold.
- Added offscreen WPF layout smoke for all five windows, checking application icons and titles across four synthetic scales.
- Extended Windows CI and preview-release pipeline to run both new test suites.
- Not a Stable release: VM execution of a real version-to-version update, native display DPI and actual protected DLL modification remain unverified.

## 0.1.0-preview.7 — 2026-11-09

- Applied a consistent light blue/navy theme based on the user's DISM-GUI and BitKeyBridge design, with rounded controls and Segoe MDL2 icons.
- Added the version to every window title and the ICO to all dialogs; improved main toolbar wrapping and layout.
- Implemented administrator-confirmed EXE replacement from a protected Program Files folder: SHA-256 verified, versioned GitHub preview asset, current-version helper, pre-replacement backup, offline health probe and attempted rollback on failure.
- Added opt-in successful-fix compatibility metadata, manual GitHub Issues submission, and aggregated version CSV workflow. No device/user identities, addresses or raw files are sent.
- Expanded Windows CI: updater ZIP and CLI probe smoke tests, version-only report parser, and new XAML views.

## 0.1.0-preview.6 — 2026-11-08

- Added opt-in, reviewed diagnostics submission to a pinned GitHub Issues endpoint, using only a temporary session token.
- Added status reconciliation for submitted reports and fully offline HTTP-mock regression tests.
- Fixed cross-thread WPF diagnostics input access and invalidation after editing.
- Isolated NSudo's executable DLL cache from the audit/log directory with protected ACLs.
- Expanded XAML event checks and clarified test coverage and remaining real-VM acceptance steps.

## 0.1.0-preview.5 — 2026-11-08

- Imported the UniversalDiagnostics and UniversalUpdater cores with a WPF adapter.
- Embedded the verified official NSudo 8.2 x64 binary into the single-file Windows preview.
- Disabled legacy takeown/icacls fallback and required a verified executable-section preview before Apply.
- Automated Windows build, synthetic tests, read-only EXE smoke test and third-party license packaging.
