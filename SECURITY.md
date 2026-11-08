# Security policy

This project edits a protected Windows Remote Desktop system DLL. Treat it as a high-impact system utility, **not** a general-purpose RDP access tool.

- Only use on systems you manage and are licensed to modify.
- Do not apply a signature by resemblance or from fuzzy scan results.
- Do not publish a real `termsrv.dll` or a report with hostnames, usernames, network addresses or other private environment details in GitHub issues.
- Report vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting if enabled. Otherwise open a minimal issue **without reproduction secrets** asking for a private reporting channel.
- Never ask users to disable NLA or enable blank-password RDP login to make the patch work.
- Release artifacts built by GitHub Actions are unsigned preview binaries, not proof of safety or licensing compatibility.

No public release should be called stable before Windows VM patch and rollback tests pass.
