# Windows smoke-test checklist (manual, disposable VM only)

This checklist is for a throwaway Windows 10/11 x64 VM. It is not a recommendation to use the patcher on licensed production systems.

## Read-only checks (do first)

1. Use a **local console** with an Administrator account and take a VM snapshot.
2. Run `dotnet restore TermsrvPatcher.Unified.csproj`.
3. Run `dotnet run --project Tests/TermsrvPatcher.Tests.csproj -c Release` and require PASS.
4. Run `dotnet publish TermsrvPatcher.Unified.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish`.
5. As an ordinary (non-admin) user, run `publish\TermsrvPatcherUnified.exe --inspect-file "C:\Windows\System32\termsrv.dll" --report "C:\Temp\termsrv-inspection.txt"` (create `C:\Temp` first if required). Check the report and verify it describes the correct version/hash.
6. Open the GUI. Check scaling at 100%, 125%, 150%, and 200% DPI; resize the window and restart. Labels, tabs and buttons must remain visible.
7. Press **Check DLL**. A `Ready` or `AlreadyPatched` state is **only a signature match**, not an assurance that Microsoft's session restrictions or licensing permit the change.
8. If state is `Unknown`, confirm Search DLL displays read-only markers and (where possible) near-match hints. Confirm **Apply verified patch** remains disabled.
9. Enter an invalid manual pattern (single-digit HEX, mismatched group lengths, all wildcards). Confirm it cannot be applied. Import a copy of the legacy pattern file and check that it remains manual only.
10. Export and copy the scan report. Verify the output file is readable and no DLL modification occurred.

## Destructive test (separate, explicitly authorized VM test only)

- Do not test from an active RDP-only connection: TermService will be stopped.
- Verify the test VM license allows the intended use and have local/console recovery access.
- Make a snapshot and record `Get-FileHash C:\Windows\System32\termsrv.dll -Algorithm SHA256`.
- Test a known exact supported pattern; don't force unknown signatures or patch bytes based on near matches.
- Verify the backup filename/hash, NTFS ACL, DLL SHA-256 after application, and service restart status.
- Restore the verified backup and compare the original SHA-256 and file permissions.
- Test negative paths: no pattern, duplicate hits, PE header signature, non-executable-section signature, stale preview (DLL changed between preview/apply).
- Do not add automatic SYSTEM scheduled tasks until unattended operation and recovery are independently audited.

## Pass/fail

No live Windows VM test has been performed as part of the preview. GitHub Actions on `windows-2025` checks build, synthetic read-only behavior, and packaged executable inspection, **not** live `TermService` stopping or patching.

## Preview.7 GUI and updater manual tests

- At 100%/125%/150%/200% DPI, verify all window titles display the version, toolbar icons are visible, labels do not overlap, and light colors remain readable.
- On Windows x64, run the preview from a controlled Program Files subfolder. Verify **Check** discovers a newer valid preview release only when GitHub Releases is accessible; missing Releases must not be labelled up to date.
- Click **Install** only on a disposable VM with a snapshot and administrator rights. Verify explicit unsigned-preview warning, separate single-EXE ZIP SHA-256, old EXE backup, app shutdown, replacement, and successful `--update-probe` validation.
- Intentionally fail a probe on a disposable VM and verify automatic rollback and a recorded failure hold. Verify attempts from a user-writable folder are blocked.
- After an explicitly authorized successful Apply, review the compatibility dialog. Confirm it includes only Windows name/release/build/UBR, `termsrv.dll`, DLL version, application version and fix mode. Skip must do no network I/O. A submitted token must never be stored in the local log or report.

## Preview.8 updater and high-DPI acceptance

- On Windows 11, install preview.7 in a protected Program Files subdirectory; confirm preview.8 is offered through Check → Install. A standard Users: ReadAndExecute ACL must *not* disable Install. Verify preview.8 launches and preview.7 remains in the backup file after successful replacement.
- Use a disposable VM/snapshot to simulate failed post-update self-test and confirm recovery of the previous EXE and failure hold. The synthetic CI test does not replace an actual running application.
- Inspect each of the five windows at real desktop scaling 100%, 125%, 150%, 200% for icon visibility, readable text and unclipped commands. CI only measures offscreen layouts at synthetic scale factors.

## Preview.9 read-only verification (already completed in GitHub Actions)

- Published preview.9 inspected the actual Windows Server 2025 runner `termsrv.dll` without changing the DLL SHA-256, ACL, TermService status or protected native cache.
- The published distribution ZIP SHA-256, real DLL file version and SHA-256 in the generated report were verified; invalid output extension/missing DLL input were rejected.
- For a proper Windows 11 acceptance test still use a disposable **Windows 11 x64 VM with console access and snapshot**, compare original and restored DLL SHA-256, service states, backup file integrity, and UI at actual 100–200% display scaling. Do not run destructive tests on a production RDP-only machine.

## New backup and Restore acceptance gate

- An isolated GitHub Actions Windows test copies the runner's real `termsrv.dll` into a temporary folder and checks the same backup store used for actual Apply/Restore. It never invokes the elevated DLL writer.
- Verify on an authorized disposable Windows 11 VM with snapshot: with **Create backup** on, a checksum-named original DLL exists; with it off, no new persistent backup is created. Validate Restore after a completed Apply, original DLL hash, file permissions and RDP service state. Avoid remote-only recovery paths.
- Check that a corrupted, renamed, version-mismatched, or externally located backup never becomes a selectable Restore source.

## Preview.14 transactional RDP Settings acceptance (disposable Windows 11 VM)

**Only on a disposable Windows 11 x64 VM with snapshot and local/console access.** Automated Windows Server 2025 CI exercises synthetic service and setting failures; it cannot prove the real RDP service and Group Policy lifecycle.

1. Record the original `fDenyTSConnections`, `fSingleSessionPerUser` and `RDP-Tcp\UserAuthentication` DWORD values **including whether each value is absent**, plus the enabled state/profile scope of actual Windows Firewall Remote Desktop inbound rules. Capture the applied Group Policy separately.
2. Open **RDP Health → Check RDP configuration** first. Verify the policy/local discrepancy, current TermService state, missing values and unsupported policy settings are reported as evidence, not proof of effective Group Policy.
3. On a VM with a known conflicting RDP Group Policy value, try the **RDP Settings → Save** path with a mismatched selection. Expected: an explicit conflict error and **no changes** to any RDP registry value or firewall rule.
4. With a known policy-compatible test configuration, use **Save settings** and verify the resulting DWORDs and applicable Domain/Private inbound rule state independently. Verify current values are shown after Save, not just the requested checkboxes.
5. Repeat with an intentionally invalid/unsupported local DWORD type in the disposable VM. Save must refuse **before modifying any other setting**. Restore the clean VM snapshot afterward.
6. Exercise the provided `--rdp-transaction-qa` synthetic fault injection and verify the error distinguishes completely verified rollback from **incomplete** recovery. Do not inject actual service/registry failures on production computers.
7. For authorized protected DLL Apply/Restore testing, separately record original DLL hash/ACL and running/stopped RDP companion service states, take another snapshot, keep local console access, and verify service states and file contents after both operations. These live tests are **not covered** by GitHub-hosted CI.
8. Verify actual Windows desktop scaling at 100%, 125%, 150% and 200% on-screen, including the RDP Health and History tabs. CI tests only offscreen WPF layouts.

## Preview.15 Manual HEX Viewer acceptance — Windows 11 GUI

Use an isolated Windows 11 x64 VM with local console access. Do not test protected DLL modification simply to verify the viewer.

1. Open **Automatic → Check DLL** on a DLL that returns `Ambiguous`. Confirm the read-only evidence table lists all three embedded signature families, exact Find and Replace counts, individual offsets and any repeated/conflicting candidates. **Apply** must stay disabled.
2. Open **Manual**, type a partial Find such as `39 81 3C 06 00 00 0F` and wait for the live results. The selected result should show a 16-byte `00–0F` grid, eight-digit address column and aligned ASCII dump.
3. Refine the Find with `*` or `??` (one whole byte). The typed Find mask and the **actual file bytes** must appear separately. Fixed-byte positions and wildcard positions must have different highlight colors, including matches spanning two 16-byte rows.
4. Select another result, then use **Previous match**, **Next match**, and **Copy actual HEX**. Verify copied bytes represent the chosen file content, not a proposed replacement.
5. Type only one fixed byte, an incomplete nibble and an invalid HEX token: broad/incomplete input must stay bounded and fail harmlessly, with no guessed replacement bytes or enabled Apply.
6. **Import patterns...** with a Patches.txt fixture containing multiple OS/DLL build labels. **Check all imported** should examine every imported entry, show exact vs missing bytes and distinct OS-build/DLL-version hints, then at most suggest a uniquely verified compatible candidate for review. **Check selected** must remain a separate operator action.
7. Repeat at actual Windows display scaling 100%, 125%, 150% and 200%. Confirm the HEX viewer has usable horizontal/vertical scrolling, the header aligns with its 16 byte cells, no text/buttons are clipped, and the view stays responsive to repeated searches.
8. Verify **Diagnostics → Open GitHub (sign-in needed)** accurately indicates GitHub authentication is required. There is no anonymous intake backend in this Preview.

These are manual GUI acceptance tests. CI supplies synthetic HEX/parser bounds and headless WPF layout checks, but cannot certify the visible 200% screen rendering or Windows 11 protected DLL behavior.

## Preview.17 — SHA-bound Automatic-to-Manual HEX and evidence export

Use a disposable Windows 11 x64 VM with console access and a clean baseline. **Do not patch the protected system DLL merely to exercise these read-only features.**

1. Open **Automatic → Check DLL** for a known `Ambiguous` DLL. Select each group in the evidence table. **Inspect selected Find in HEX** should be available only when Find hits exist; **Inspect selected Replace in HEX** only when Replace hits exist.
2. Select a signature and open it in **Manual**. Verify that the 16-column HEX/ASCII viewer highlights the real matched bytes and wildcard bytes, and that the **Manual Replace field is empty**. Neither the selected pattern nor a compatible version label should enable Apply.
3. Check the Automatic/Manual reported SHA-256 against an independent hash from an unmodified file copy. Deliberately replace only the test file between inspection and export; old evidence must be rejected and a fresh Check requested.
4. Choose **Export signature evidence** and save to a new `.txt` path. Verify schema, Windows/DLL version, hash, group Find/Replace signatures, offsets and near-match counts. Review for user/computer paths and identifiers before sharing. Existing files must not be overwritten, and no report is uploaded automatically.
5. Recheck at real Windows display scale **100%, 125%, 150% and 200%** with the actual GUI visible. Confirm selection/navigation/scrolling and all new buttons fit, including long signature text.
6. Validate **Updates → Check → Install** eligibility messages and **Open GitHub release** fallback from Preview.16 still behave as documented. The updater may require an elevated trusted installation path.
7. Keep actual protected DLL Apply/Restore, service restart, RDP connection, and GPO/firewall acceptance separate; none of these is demonstrated by the GitHub-hosted read-only test.
