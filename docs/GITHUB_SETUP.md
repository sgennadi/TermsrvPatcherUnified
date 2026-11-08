# GitHub destination

Repository: https://github.com/sgennadi/TermsrvPatcherUnified
Branch: main
Visibility: public

This repository **already exists**. Do not create a replacement or rename it.

The source includes a Windows build workflow under `.github/workflows/windows-ci.yml`.
It performs offline validation, .NET synthetic tests, publishes a read-only-smoke-tested
Windows x64 executable to a **workflow artifact**, not to a public GitHub Release.

Shared integrations are vendored under `Shared/UniversalUpdater.Core` and
`Shared/UniversalDiagnostics`; no private-repository checkout or tokens are
required for GitHub Actions. License and upstream provenance are documented in
`NOTICE.md` and `README.md`.

For local development, use `dotnet restore`, `dotnet run --project Tests`,
and `dotnet publish` as documented in README. Always test system DLL changes
on a disposable Windows VM with local console access.
