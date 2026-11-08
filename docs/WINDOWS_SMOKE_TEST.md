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
