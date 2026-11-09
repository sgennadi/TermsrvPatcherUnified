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
