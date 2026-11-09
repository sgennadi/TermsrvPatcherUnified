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

## Preview.22 recovery boundaries

- Full original DLL backups are optional only after explicit operator warning and confirmation; automatic Apply never skips its protected, SHA-bound compact journal. On-disk journal encryption uses Windows DPAPI LocalMachine plus restricted directory ACLs; encryption without protected key/ACL management is not a general-purpose tamper defense.
- `System32\\termsrv.dll.bak` is managed only as a verified copy, never renamed into place automatically. Windows Update may change the installed DLL independently; old `.bak` files must be archived before any rotation, never trusted merely by file name or CRC32. Check is read-only.
- If the full backup and journal are both missing, only fully known fixed bytes of a unique embedded 13/19-byte signature can be deterministically reconstructed. This does **not** authenticate the resulting file as a Microsoft original, and a second explicit confirmation is necessary. Wildcards, unknown releases, partial or conflicting matches must refuse. Use verified Windows component-store repair or a trusted original/snapshot otherwise.
- Protected Revert can disconnect RDP. The isolated SYSTEM worker is intended to continue after GUI logoff but cannot survive system power loss or OS termination. Do not test on a machine whose only recovery route is RDP. No live Windows 11 protected Revert certification is claimed.
