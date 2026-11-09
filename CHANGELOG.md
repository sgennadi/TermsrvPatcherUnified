# Changelog

## 0.1.0-preview.18 — 2026-11-09

- **Automatic selection:** when an installed Windows 11 24H2, 25H2 or 26H2 Client has one exact version-specific embedded signature and an unrelated older Generic fallback also matches, build the Apply preview for only the specific target instead of blocking with cross-profile Ambiguous. Show the selected profile and explicitly state that Generic remains unchanged. A unique exact Generic match remains eligible.
- **Fail-closed conditions:** do not guess among two distinct specific profiles, untrusted imported signatures, overlapping edits, repeated Find/Replace hits, mixed original/replaced states or unknown installed OS contexts. Manual and offline scans do not inherit automatic OS-specific precedence.
- **Catalog corrections:** the Generic Find mask fixes the 0F 84 JE/JZ opcode (not wildcard) while permitting three variable displacement bytes; the operator-supplied manual-only Windows Server 2022 20348.3091 legacy signature now ends with 00 instead of erroneous 20. Do not equate Windows OS build with termsrv.dll file version.
- **Diagnostics:** separate profile-level exact matches from within-profile collisions, report offsets and fixed-byte counts, and retain read-only evidence. The Generic/25H2–26H2 case is tested at the operator-reported offsets 0x0006D20A and 0x000A6896 using synthetic bytes. The Windows 11 system DLL has not been patched or functionally tested in CI.
- Existing backup, original-hash, executable-section, permission and rollback checks remain mandatory. **Unsigned Preview, not Stable**.


## 0.1.0-preview.17 — 2026-11-09

- **Automatic → Manual HEX:** select a matching Find or Replace signature and inspect its existing bytes in Manual's read-only 16-column HEX/ASCII viewer. The workflow clears the Manual Replace input; no replacement is inferred, approved or applied automatically.
- **Export signature evidence:** save a locally reviewed `termsrv-signature-evidence/v1` text file with Windows/DLL versions, SHA-256, masked Find and exact Replace signatures, hit counts, offsets and bounded near-match details. No anonymous upload; source paths, usernames and host identifiers are not included as report fields.
- **SHA-256 consistency:** compare the engine preview, separately read signature snapshot and fallback scan; reject outdated evidence when the DLL changes. A failed check must not leave an old Ready plan available.
- **Windows QA:** simulated hash mismatch, file change, report-label redaction, CRLF/LF, no overwrite, TXT-only output; 55 signature tests and 20 offscreen WPF viewports passed in earlier CI. The final Preview.17 build and release still require their own checks.
- Preserves Preview.16 updater eligibility explanations and the safe **Open GitHub release** fallback. No real Windows 11 protected Apply/Restore or physical 200%-DPI acceptance yet. Unsigned Preview, not Stable.


## 0.1.0-preview.16 — 2026-11-09

- The updater now explains the exact reason when **Install** is disabled: missing live release data, cached results, insufficient elevation, unsupported/unsafe installation path, or previous failure hold.
- Added **Open GitHub release** as a manual fallback for standalone ZIP installations (no automatic elevation or downloads triggered).
- Corrected the misleading initial warning about requiring a signed installer: Preview packages remain **unsigned** and are installed only after explicit approval and integrity checks.
- Enlarged the Updates window and wrapped explanatory text; expanded offscreen WPF QA to check the new eligibility message and release button.
- This does not relax the administrator/protected Program Files safeguards, and does not modify DLL patching or short-HEX Find behavior. The Manual live Find search remains read-only; full Find/Replace validation still requires four matching byte positions.
- Real Windows 11 display scaling and protected Apply/Restore remain manual acceptance tasks.


## 0.1.0-preview.15 — 2026-11-09

- **Automatic → Signature evidence:** lists each catalog Find/Replace signature, its exact-match count, offsets and reason for repeated or conflicting results. An ambiguous match stays blocked; none of these read-only findings authorizes Apply.
- **Manual → live Find:** incremental partial-HEX lookup in the installed DLL with `*` and `??` wildcards, capped candidate counts, real byte context and masked fixed-byte positions. Incomplete input is not silently converted into a replacement.
- **Manual → HEX Viewer:** Notepad++-style 16-byte address rows, hexadecimal 00–0F header, ASCII dump and separate highlighting for fixed bytes versus wildcard bytes, plus Previous/Next and Copy actual HEX. Data comes from one inspected DLL snapshot; no file write or service interaction occurs.
- **Manual → imported catalogs:** **Check all imported** checks every profile against actual DLL bytes, PE executable sections and Windows/build/DLL-version hints; lists candidates and suggests a uniquely verified one for review, never automatic application.
- GitHub reporting now explicitly labels the GitHub sign-in/token requirement; anonymous GitHub Issue creation is not enabled without a separately operated intake service.
- Windows CI and release pipeline gain read-only signature, imported catalog, HEX viewer and synthetic WPF control tests. Real Windows 11 desktop DPI and live Apply/Restore remain manual acceptance gates.


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
