# Changelog

## 1.0.0 — 2026-11-10 (Stable release candidate)

- **UI:** wider Simple and Advanced windows, fixed Simple action footer, work-area sizing for high-DPI displays and scrollable modern confirmation dialogs.
- **Updates:** Stable/Preview selection plus visible **Updates • NEW** badge in both Simple and Advanced. Channel/version tooltips distinguish cached from live results. Installing requires a fresh, operator-approved, verified release and rollback safety.
- **RDP policy diagnostics:** read-only winning GPO source, registry value, GUID and precedence when Windows RSoP is available. Unknown GPO identity never authorizes overriding a policy. Local edits use an approved registry-value allowlist, verification and rollback.
- **Reports:** opt-in typed metadata via Google Apps Script to public GitHub Issues; production delivery to Issue #32 was observed, recorded as **unverified compatibility evidence** only, not proof of patch success.
- **Safety:** exact-signature restrictions, protected recovery, full backup by default, no unattended scheduled task by default and session-independent protected worker for approved RDP operations.
- **Tests:** Windows Server 2025 CI includes synthetic and read-only tests, UI smoke, backup integrity, offline DLL inspection, portable updater verification and a non-destructive SYSTEM/Session 0 worker test. Live Windows 11 System32 writes, RDP reconnection and physical high-DPI rendering require separate manual validation.
- **Distribution:** unsigned Windows x64 single EXE; portable ZIP containing only EXE and Example.txt, updater ZIP containing only EXE, plus SHA-256 sums. Respect Microsoft licensing.

## 0.1.0-preview.28 — 2026-11-10

- **Google reporting instead of Formspree:** the operator-supplied Google Apps Script deployment URL is embedded in the EXE and produces a public GitHub Issue only after the user reviews the exact typed report and confirms sending.
- **Remove obsolete provider:** no Formspree endpoint, ID, transport, or user-facing text is compiled into the application. The former public ID is archived in source documentation, not shipped in the executable.
- **Verified delivery:** support the Google ContentService redirect only to the expected Google response host; accept delivery solely with a validated Issue URL for this repository. No hidden uploads, retries, or local-save requirement.
- **Diagnostics:** Windows build, UBR, DLL version and SHA-256 remain selected by default. The current deployed v1 gateway requires these values; unchecking them disables direct Google send instead of inventing evidence. Optional GitHub OAuth and manual local reports remain in Advanced.
- **Testing:** synthetic HTTP and UI tests cover trusted redirects, malicious responses, consent data, and stable-updater packaging. Live Google / GitHub acceptance is not claimed without a user-approved production submission.

## 0.1.0-preview.27 — 2026-11-10

- **Revert status:** successful authenticated Restore/Revert explicitly uses green, failures use red, and catalog-only reconstruction without verified original uses amber. Checking resets stale status colors.
- **Success sharing:** after confirmed local console Apply in Advanced, offer an optional short Formspree report. Successful manual Apply now opens a friendlier dialog with primary optional Formspree review and the former detailed public GitHub metadata submission retained under Advanced.
- **Privacy:** neither a completed Apply nor an optional reporting dialog triggers an upload. The operator must still review the exact fields and explicitly approve Formspree sending. No local report file or account is required for Formspree.
- **Verification:** WPF smoke tests confirm that the new success dialog has optional Formspree sharing and retains the existing advanced GitHub controls. Tests do not modify system DLLs or Task Scheduler entries.

## 0.1.0-preview.26 — 2026-11-10

- **Task Scheduler ACL:** register SYSTEM Auto Reapply with TASK_DONT_ADD_PRINCIPAL_ACE, apply a protected task ACL explicitly and re-check the task. Existing tasks with our expected action, SYSTEM identity, schedule and protected worker may be repaired only with a separate administrator confirmation. Unknown tasks remain blocked.
- **Simple UI:** verified backup, recovery journal, Revert availability and successful Apply have green statuses. AlreadyPatched without authenticated recovery remains red; diagnostic task failures remain warnings.
- **Direct Formspree:** Windows build, DLL version and SHA-256 option is checked by default but can be unchecked. Send now builds a typed report in memory, previews exact JSON and requests confirmation; no mandatory local save, login or auto-retry. Formspree success does not create a GitHub Issue or update the compatibility CSV.
- **After Apply:** only after independently confirmed success, the app may offer to share a small compatibility report. Declining sends nothing. Reopened Simple view provides an optional Share button for a recorded successful Apply.
- **Tests:** synthetic task-ACL, no-disk diagnostic and Windows WPF smoke tests. Actual scheduled task repair on the user's host still requires hands-on verification.

## 0.1.0-preview.25 — 2026-11-10

- **Task Scheduler:** recognize absent Auto Reapply tasks when Windows COM reports `FileNotFoundException` / known task-not-found HRESULTs during `GetTask`. Show `Scheduled task: Not configured (optional)` instead of a technical error. Do not treat access-denied, service faults or missing worker files as absent tasks.
- **Status:** show AlreadyPatched / Already patched in red in Advanced and Simple; no change to patch or restore eligibility.
- **Diagnostics:** explain the two required steps: Review and save locally, then Send report via the preconfigured Formspree form. Nothing is automatically uploaded.
- **Verification:** add synthetic missing-task vs access/service-failure cases; tests do not register or modify Windows scheduled tasks.

## 0.1.0-preview.24 — 2026-11-10

- **One-time embedded configuration:** administrator sets the nonsecret public provider IDs once using `scripts/Configure-Reporting.ps1` and GitHub Actions Variables; each subsequent CI/release build embeds them in the EXE. No per-user ProgramData reporting.json, extra file, input box or installation script. Missing IDs disable providers; browser login and reviewed send remain mandatory.
- **No self-hosted receiver required:** add Formspree submission of canonical typed diagnostics (explicitly consented Windows build / DLL SHA-256 optional) and direct GitHub Issues with OAuth App Device Flow, no manual PAT required for OAuth. GitHub token only held in dialog memory. OAuth `public_repo` access is broader than Issues; the permission warning appears before login.
- **Separate acknowledgements:** Formspree's `ok=true` acknowledgement records a Formspree-only local delivery with no invented GitHub Issue URL, while GitHub still requires a validated, repository-pinned Issue receipt. Neither provider silently retries or auto-sends, and Formspree does not update GitHub CSV.
- **UX and testing:** provider configuration IDs (nonsecret), browser code/cancel/copy, exact outgoing Formspree JSON preview, safe disabled defaults and synthetic network tests. Relay and advanced PAT methods remain optional.
- **Preview boundary:** the supplied Formspree endpoint `https://formspree.io/f/mvkkernb` is embedded; the form was not submitted to in live tests. GitHub OAuth remains disabled without an OAuth App client ID; no Windows 11 protected patching has been certified.

## 0.1.0-preview.23 — 2026-11-10

- **Simple GUI:** rebuild the compact startup window with separate Patch and Status cards, concise Automatic Pattern Recognition, backup and Auto Reapply options, and Cleanup/Updates/Advanced actions. Advanced has a direct **Back to Simple** button and preserves the no-backup selection in both directions.
- **Consolidated Remote Desktop:** replace separate RDP Settings/Health tabs with one status/settings/health/policies/sessions page, with advanced read-only inspection of additional Windows and Group Policy parameters. Local blank-password restriction has a guarded, explicitly confirmed setting, verified readback and rollback.
- **RDP post-save actions:** show precisely which local settings changed, whether next-session testing is advised, and when observed listener-port drift requires restart review. Add explicit, administrator-confirmed computer-only `gpupdate` with bounded wait and a post-refresh RDP/GPO readback. Never automatically stop TermService, log users off or reboot when clicking Save or refreshing policy.
- **Auto reapply after Windows Update:** opt-in main checkbox registers an administrator-only SYSTEM task and copies the current EXE to a protected ProgramData worker directory. Triggered by Windows Update event 19 (30-minute delay), Windows boot (15-minute delay), and a daily fallback. A changed DLL must match a trusted automatic profile exactly before any write, and **full backup is mandatory** regardless of the manual no-backup option. Pending reboot, unknown signatures and competing protected jobs block changes.
- **Cleanup:** explicit categories for protected DLL backups, local reports/history and the persistent Auto Reapply task; task deletion is independently selectable (OFF by default) and separately confirmed. No Windows event-log or external-file erasure. Protected Apply/Revert tasks block Cleanup while pending, active or unconfirmed.
- **Portable updates:** permit manually approved self-update from local Desktop/Downloads/other regular local directories, while continuing to refuse network and linked targets. The verified updater helper remains in protected ProgramData; a successfully installed EXE refreshes an already-opted-in SYSTEM task copy.
- **Backup restoration:** improve disambiguation across valid backup generations, tolerate a replaced System32 .bak only when it equals a separately verified current original, and allow independent trusted backup recovery if a journal is corrupt.
- **Verification boundary:** GitHub Actions uses synthetic .NET/WPF layouts, read-only policy and DLL checks and non-destructive Task Scheduler probes. Actual Windows 11 DLL modification, permanent post-update Task Scheduler operation and live RDP recovery still require isolated Windows 11 testing. No Stable release is implied.


## 0.1.0-preview.22 — 2026-11-09

- **Quick Revert and compact no-backup:** add Revert beside Apply, Check and Advanced, and an unchecked-by-default `Do not create backup` box. A separate confirmation is required before skipping full DLL backups. Advanced Apply honors the same choice. Automatic Apply always saves a small encrypted/authenticated per-version recovery journal before system writes.
- **System32 full copy and servicing-aware rotation:** optional full original `termsrv.dll.bak` in System32 plus protected ProgramData backup, both checked by SHA-256. At the next explicitly approved Apply after a Windows Update, archive the previous indexed `.bak` and verify the new current original before updating. Check never writes or silently replaces `.bak`; mismatched/truncated/tampered backups fail closed.
- **One-click Revert by proof:** exact journal first; otherwise verified protected backup or indexed System32 copy. Re-verify source SHA, target SHA, current DLL version and length at dispatch and inside protected transaction. Remote Revert gets a separate one-shot LocalSystem/Session 0 worker, including clear Queued/Running/Succeeded/Failed statuses. An arbitrary manual Restore still requires the local console.
- **No backup AND no journal:** only uniquely reversible, fully fixed known Windows 11 24H2 (13-byte) or 25H2/26H2 (19-byte) signatures may reconstruct their known source bytes. Cross-check one target by reapplying and comparing the entire current DLL, enforce executable PE bounds, disallow wildcard Generic / unknown Windows families / mixed / repeated / overlapping matches, require a second explicit high-risk confirmation. This cannot attest a genuine Microsoft-supplied original file: label separately as `RevertReconstructed`. For other states, refuse and recommend signed system component repair/SFC or offline recovery.
- **QA boundary:** new pure, read-only synthetic pattern-reversal and WPF controls tests plus existing Windows CI; no live Windows 11 protected DLL write, RDP disconnect/reconnect, real System32 copy rotation or physical 200% DPI validation. **Unsigned Preview, not Stable.**

## 0.1.0-preview.21 — 2026-11-09

- **Context-aware protected Apply:** the current interactive Windows session is checked with the WTS client protocol and remote-session metric immediately before dispatch. A confirmed console session retains the original Apply path; RDP and unknown sessions use an explicitly approved, one-shot SYSTEM Task Scheduler worker in session 0.
- **Compact startup:** when an exact trusted automatic profile is Ready, display only Apply / Check / Advanced / Cancel plus DLL status. Advanced keeps all evidence tables, Manual, Offline, Diagnostics, updater and settings. Starting the program alone does not modify Windows.
- **Isolated worker:** protected staging of a self-contained EXE, strict task ACL and LocalSystem identity, independent re-inspection of the original DLL, source and expected-result SHA-256 checks, exact signature and version checks, mandatory protected backup, one-shot execution lock and locally saved result. Uses existing NSudo Devil Mode 8.2 and service rollback. GUI or RDP disconnect does not cancel a successfully started task.
- **Headless `--reapply`:** an approved direct SYSTEM task and local console keep their normal execution; invoking `--reapply` from RDP queues the protected one-shot SYSTEM job and returns exit code 6 (deferred, not yet applied).
- **Manual/Restore RDP safety:** do not attempt their interactive path in a remote session until independently isolated workers exist; those actions remain available at the local/VM console.
- **Backup ACL fix:** place trusted DLL backups in a separately protected ProgramData directory instead of under the potentially user-writable audit-log directory. Legacy files are untouched and not silently migrated.
- **Test boundaries:** synthetic session classification, path tamper refusal, WPF quick UI and real-DLL-copy backup tests, plus a **real non-destructive Task Scheduler smoke** that launches the published EXE as LocalSystem in session 0 on Windows Server 2025. No Windows 11 protected DLL write, actual RDP disconnect/reconnection or live Restore has been certified; isolated-VM acceptance is still required.

## 0.1.0-preview.20 — 2026-11-09

- Integrated the **byte-for-byte canonical UniversalDiagnostics v1 anonymous HTTPS relay client** from `sgennadi/UniversalDiagnocticsModule` into the single-EXE application. Existing local capture and user-reviewed authenticated GitHub reporting remain intact.
- Diagnostics now shows **Send anonymously** and relay configuration state. The button remains disabled without a configured HTTPS endpoint and a locally saved, validated report. A separate confirmation shows the *exact typed JSON* about to be sent; free-text descriptions, raw logs, paths, hostnames and credentials are excluded.
- The transport disallows HTTP redirects, cookies, plaintext URLs and untrusted receipts; it requires a matching project/event ID and public GitHub Issue URL before recording successful submission. Failed or uncertain submissions stay locally pending.
- Offline tests cover redacted payloads, no client token, fingerprint/endpoint failure, receipt rejection, WPF state and existing backup/updater safety. **The separate Cloudflare Worker relay is not deployed**, so live anonymous delivery is not claimed.

## 0.1.0-preview.19 — 2026-11-09

- **Automatic Apply priority list:** fixed read-only ordered rows for trusted 19-byte 25H2/26H2, 13-byte 24H2, Generic 12-byte profiles, plus a separate externally sourced 12-byte Hot Patch reference. Shows exact Find/Replace hit counts, offsets, selected/skipped/blocked decisions and explanations.
- Priority depends on the installed Windows family; the table never changes the existing one-target PatchCatalog plan, PE checks, SHA-256 checks, backups or rollback.
- The new 12-byte Hot Patch reference is observation-only and never authorizes a protected disk edit or an in-memory write. It can coincide with the 12-byte suffix of the trusted 19-byte 25H2/26H2 pattern, and remains independently non-authoritative.
- Synthetic regression QA covers 24H2/25H2/26H2 ordering, the external 12-byte suffix at 0x000A689D, blocked ambiguity, and Server 2025 inspect-only state. WPF offscreen test checks fixed order and view-only selection.
- No live Windows 11 protected Apply or RDP session test is claimed.

## 0.1.0-preview.18 — 2026-11-09

- **Packaging:** portable ZIP contains exactly `TermsrvPatcherUnified.exe` + `Example.txt`; full GPLv3/MIT texts and notices are appended to the latter. The updater ZIP remains one EXE. Both build paths use the same exact-content validator, with negative tests.
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
