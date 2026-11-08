# Preview QA status — 2026-11-08

Version: 0.1.0-preview.6

## Verified already for preview.5 (GitHub Actions)

- Windows x64 build, .NET 10 restore, synthetic signature and PE safety tests passed.
- Official NSudo 8.2 x64 archive downloaded from pinned source and verified with SHA-256.
- Self-contained single-file x64 EXE published, read-only CLI inspection smoke-tested.
- Result: https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42525859642

## Changes being verified for preview.6

- Opt-in GitHub Issue creation using a temporary Issues:write token, no automatic delivery.
- Response URL pinned to this repository, unknown or redirect statuses fail closed.
- Local diagnostics queue is acknowledged only after confirmed successful submission.
- GitHub requests are tested with a fake HTTP handler; CI makes no real Issue POST.
- The WPF diagnostics window captures description text on the UI thread before background processing.
- NSudo extraction uses a dedicated admin-protected `%ProgramData%\TermsrvPatcherUnified.NativeProtected` directory, separate from audit logs.
- XML/XAML checks, source-format verification and mocked transport tests are run in Windows CI.

## Not verified / must remain Preview

- No actual patch, restore, remote login, service stop/restart or NSudo hook lifetime test on a real Windows 11 VM.
- No end-to-end GitHub Issue publication with a real operator-owned token (the workflow uses offline stubs).
- No Authenticode signer-validated updater installer; Install remains disabled.
- Automatic signatures from upstream are byte-pattern matches, not guarantees for all Windows builds.
- This preview should not be deployed broadly or made Stable without a manually supervised isolated VM acceptance test.
