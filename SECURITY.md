# Security policy

This project edits a protected Windows Remote Desktop system DLL. Treat it as a high-impact system utility, **not** a general-purpose RDP access tool.

- Only use on systems you manage and are licensed to modify.
- Do not apply a signature by resemblance or from fuzzy scan results.
- Do not publish a real `termsrv.dll` or a report with hostnames, usernames, network addresses or other private environment details in GitHub issues.
- Report vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting if enabled. Otherwise open a minimal issue **without reproduction secrets** asking for a private reporting channel.
- Never ask users to disable NLA or enable blank-password RDP login to make the patch work.
- Release artifacts built by GitHub Actions are unsigned preview binaries, not proof of safety or licensing compatibility.

No public release should be called stable before Windows VM patch and rollback tests pass.


## Preview updater trust model

- Unsigned preview EXEs are not publisher-authenticated. The GitHub Releases SHA-256 digest and strict updater ZIP/x64 PE format are checked, but this is not a substitute for Authenticode.
- Installation requires a live release check, elevated administrator, an administrator-protected Program Files installation folder and explicit user confirmation; do not enable silent updates.
- Manual successful-fix metadata is publicly self-reported and should never be treated as independent proof of licensing, compatibility or safety. Public comments contain only version information.

## Offline DLL file mode

The offline workflow never overwrites the selected source DLL, changes Windows system files, invokes NSudo or stops TermService. It produces a **new** DLL only for a uniquely validated signature in executable PE sections. This does not mean the output DLL has been tested in Windows. CRC32 is useful for legacy version identification; **SHA-256 is the integrity digest**.

The optional `termsrv-offline/v1` report requires the operator to review and explicitly authorize publication with a temporary GitHub Issues-write token. It publishes architecture, DLL/app version, CRC32, SHA-256 and bounded changed byte ranges, never a complete DLL, hostname, user, path or network identifiers. These reports are aggregated separately from system-Apply success records in `data/offline-fixes.csv`.
