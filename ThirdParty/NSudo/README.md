# NSudo Devil Mode (optional native component)

TermsrvPatcherUnified pins **official NSudo 8.2 stable x64** for its Windows CI release build. No NSudo DLL is checked into this repository and no DLL is downloaded at application runtime. The CI workflow downloads the archived official GitHub release, compares the complete ZIP against a pinned SHA-256, checks the selected native DLL identity/architecture/version, and embeds that DLL as a resource into the single-file EXE.

`pwsh ./scripts/prepare-nsudo.ps1` stages `x64/NSudoDM.dll` and its SHA-256 manifest for a local Windows build; both are ignored by Git. A build without these resources runs read-only but intentionally refuses protected writes. In release CI `-p:RequireNSudo=true` makes missing resources a build error.

The original project is archived: https://github.com/M2TeamArchived/NSudo
Documentation: https://github.com/M2TeamArchived/NSudo/blob/master/Website/en-us/docs/DevilMode.md
The core NSudo repository is MIT licensed, with third-party components documented in its upstream License.md. Preserve notices when redistributing.

The DLL is extracted only on explicit protected-file write, into an access-restricted administrator-owned `ProgramData` directory. File hashes and PE x64 machine type are checked before `LoadLibrary`, and the DLL is freed immediately after the write. Never enable it for read-only scanning, automatic update checks, or diagnostics.
