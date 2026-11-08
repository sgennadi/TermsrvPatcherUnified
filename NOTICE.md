# Origin and license notices

This project is an integration/rewriting of design ideas and source logic from:

- geissbuehler/TermsrvPatcher, https://github.com/geissbuehler/TermsrvPatcher , GNU GPL version 3 as supplied in the upstream LICENSE.
- fabianosrc/TermsrvPatcher, https://github.com/fabianosrc/TermsrvPatcher , MIT, Copyright (c) 2022 Fabiano Moreira.

The three embedded automatic byte-signature families correspond to patterns in the
`TermsrvPatcher.ps1` file in fabianosrc/TermsrvPatcher at commit
affdb888270d1c2cbe0c0f7c8ccba3b6340a9f69 (2026-10-09).
The historic GUI, manual patterns, RDP settings and reversible-file-change
workflow are derived from geissbuehler/TermsrvPatcher, whose master commit was
215a02b644eee21e831ea3fd3fe6eb2c4f707900 (2025-10-20).

Modifications: reimplemented UI and patch-selection logic in .NET 10 WPF;
added read-only DLL scanner and closest-pattern diagnostics, unique-match
enforcement, manual import/save and preview, PE executable-section validation,
checksum-verified backup and a safe-by-default unknown-profile policy.
This is a preview; actual protected DLL writes have not been verified on Windows.

Project license: GNU GPLv3 (see LICENSE). MIT license text for adapted patterns:
licenses/fabianosrc-MIT.txt.

## Shared source integration (2026-11-08)

- `sgennadi/UniversalUpdater` `feature/project-audit-rc2` (v0.1.0-rc.3),
  compiled in the application as `Shared/UniversalUpdater.Core`.
- `sgennadi/UniversalDiagnocticsModule` `main` (v0.1.0-rc.3 source),
  canonical .NET `UniversalDiagnosticsEmbedded.vb` compiled as a library.

These are user-owned upstream projects and are included for source-level
integration. No private URLs, personal logs, credentials or telemetry are
embedded in the application.

## NSudo Devil Mode 8.2

Optional embedded native DLL originates from [M2TeamArchived/NSudo](https://github.com/M2TeamArchived/NSudo), MIT license (see `licenses/NSudo-MIT.txt` and the upstream third-party notices).
Release builds pin and verify the official 8.2 archive; the native DLL is not checked into this repository.
