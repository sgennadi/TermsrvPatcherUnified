# Changelog

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
