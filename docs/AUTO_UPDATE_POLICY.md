# Auto-update checks and operator approval

The checkbox **Auto-update Stable (confirm before installing)** is an
administrator-controlled machine-wide opt-in. It is **OFF by default**.

When enabled:

1. At GUI startup, check both channels for an informational badge, then make
   a fresh Stable check before offering installation. This never uses a cached
   result as installation authorization.
2. While the GUI stays open, check Stable again every 4 hours.
   If a newer Stable is verified, open the existing Update Center to review
   and explicitly approve installation.
3. If the **separate** Auto Reapply after Windows Update task is already
   enabled and trusted, a SYSTEM Session 0 run checks Stable metadata at most
   once per 24 hours. It stores the last result locally. The scheduled worker
   **does not download, execute, or replace an EXE**, restart Windows or
   alter RDP as part of release checking.
4. If Auto Reapply is OFF, there is no headless scheduled update check.
   Enabling Auto-update alone does not secretly create a SYSTEM scheduled task.

The checkbox is stored as a DWORD under
`HKLM\SOFTWARE\TermsrvPatcherUnified\Updates\AutoCheckStable`.
The last scheduled check is separately stored under the same key.
When disabled, scheduled checks stop; existing DLL backups are not affected.

**Current source trust model (1.0.8 preparation, not yet published):** both the
running EXE and the candidate must pass independently pinned Authenticode
verification. GitHub SHA-256 / ZIP / x64 PE validation, protected staging,
original EXE backup, post-install probe and rollback remain mandatory.
A self-signed certificate may still display Unknown Publisher in Windows;
a GitHub checksum alone does not authenticate the publisher.

Legacy unsigned releases cannot serve as the trusted elevated helper of the
new updater. Transition manually to an independently verified signed release
after publication. The signed source still requires explicit interactive
administrator approval; **no unattended installation** is supported, including
from a SYSTEM task.

**Channels:** Stable reads only GitHub non-prerelease releases with final
SemVer tags. Preview reads only `prerelease=true` entries with a prerelease
SemVer tag. Stale cross-channel cache entries are ignored. Both channels are
visible in Updates, but opt-in automatic offers use Stable only.

This workflow performs no telemetry uploads. GitHub release metadata checks
are ordinary HTTPS requests to GitHub; private user data is not attached.
