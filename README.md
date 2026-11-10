# TermsrvPatcherUnified

**Current source version:** `0.1.0-preview.28` · **Status:** unsigned Preview, not Stable · **Platform:** Windows x64, .NET 10 WPF

TermsrvPatcherUnified is a Windows Remote Desktop inspection and manually operated `termsrv.dll` maintenance utility. It combines exact signature inspection, manual patterns, separate offline DLL processing, protected backup/Restore, read-only system health, RDP settings and an integrated updater.

**[Download a Preview](https://github.com/sgennadi/TermsrvPatcherUnified/releases)** · **[Version history](CHANGELOG.md)** · **[Test status](docs/QA_STATUS.md)**

**Preview.28:** [direct Google-to-GitHub diagnostics](docs/DIRECT_REPORTING.md) replace the former Formspree service. An operator-approved Google Apps Script deployment is embedded in the EXE. Sending is optional, requires review of the exact metadata, and creates a **public GitHub Issue** only after Google confirms its issue URL. No end-user accounts, API tokens, or local settings are needed. Windows/DLL evidence is selected by default; disabling it also disables Google sending because the deployed v1 gateway requires complete evidence. The old public Formspree ID is kept solely in a source-code archive. Live external delivery requires separate verification.