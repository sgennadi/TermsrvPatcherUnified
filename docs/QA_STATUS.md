# Preview QA status — 2026-11-09

Version: 0.1.0-preview.7

## Existing verified baseline

- Preview.6 Windows GitHub Actions succeeded: .NET 10 WPF build, synthetic signature and PE-range tests, NSudo 8.2 archive SHA-256 verification, single-file EXE publish, and read-only DLL scan. Run: https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42562651909

## Preview.7 acceptance gates

- The main theme and all five windows must compile and render at 100%, 125%, 150% and 200% scaling; version in titles, icons readable, action buttons not clipped.
- Successful-fix reports must be generated only after Apply returns successfully, and GitHub Issues POST must use a temporary token and a fixed public issue URL. Compatibility workflow validates an allowlisted version-only schema and aggregates into `data/successful-fixes.csv`.
- GitHub CI must build the Windows EXE, run synthetic checks, and verify the exact single-x64-EXE update ZIP and offline update probe.
- The user-triggered updater installs only from an administrator-protected Program Files folder. The helper is a protected copy of the current binary; the replacement is backed up and probed before acknowledging success. Unsigned preview updates are never silent.

## Important work still requiring manual Windows VM validation

- Actual NSudo hook loading against a protected Windows DLL and TermService stop/restart.
- Live patch + restore using the exact machine's DLL version, ownership/ACL and rollback validation.
- A genuine GitHub Issues POST with the user's Issues write token and an observed CSV aggregation job.
- A genuine newer-version EXE install and forced-failure recovery test from protected Program Files.
- Authenticode signature/publisher validation: preview EXE is unsigned, manually approved only.

**Status: Preview / not authorized for broad deployment.**
