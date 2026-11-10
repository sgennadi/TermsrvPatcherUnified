# Remote Desktop setting audit (1.0.2)

This document records the inspected Windows x64 RDP configuration fields,
their source, UI behavior, editing restrictions, and suggestions for later
expansion. A registry value alone never proves a successful RDP connection.
When an ADMX policy value is absent, the UI says **Not configured/unknown**,
not **Allowed**.

## Source-of-truth and edit rules

- **Local listener**: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
  and its `WinStations\RDP-Tcp` child.
- **Computer RDP policies**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`.
  A matching computer GPO policy value blocks local editing even if local
  and policy values happen to agree. A winning GPO is attributed only from
  verifiable RSoP evidence; otherwise the source is unknown.
- **Windows local security**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse`
  is a **different security policy**, not a Terminal Services RDP policy.
  `1` enables console-only restriction, `0` disables it. Domain security
  GPOs may rewrite this local value. No winning security GPO is inferred.
  Local changes require administrator privileges, explicit consent and a
  transactional readback. A missing or malformed value blocks editing.
- An editable row is highlighted light green and has a working **Edit** action.
  Amber means a detected controlling policy. Gray means an unsupported
  edit, missing evidence, insufficient rights or a local-console requirement.
  The display state grants no authorization: the writer rechecks the value,
  GPO conflict, administrator token and relevant session restrictions.
- The **main RDP enabled, NLA and single-session** switches have their own
  shared, transactional Apply action. They are not independently writable
  through per-row editing.
- After a change, the UI re-reads the registry and policy, not the requested
  checkbox value. No automatic restart, gpupdate or reboot.

## Audited settings

| Group | Setting (display) | Registry DWORD | Edit mode |
|---|---|---|---|
| Connection | Remote Desktop | `fDenyTSConnections` | Main RDP controls, guarded |
| Connection | Network Level Authentication | `UserAuthentication` | Main RDP controls, guarded |
| Session | One session per user | `fSingleSessionPerUser` | Main RDP controls, guarded |
| Connection | RDP TCP port | `PortNumber` | Local console only |
| Connection | RDP security layer | `SecurityLayer` | Local console only |
| Security | Minimum encryption level | `MinEncryptionLevel` | Local console only |
| Security | Always request password | `fPromptForPassword` | Local allowlisted DWORD; does **not** disable authentication |
| Redirection | Disable clipboard redirection | `fDisableClip` | Computer GPO inspection |
| Redirection | Disable drive redirection | `fDisableCdm` | Computer GPO inspection |
| Redirection | Disable printer redirection | `fDisableCpm` | Computer GPO inspection |
| Redirection | Disable COM port redirection | `fDisableCcm` | Computer GPO inspection |
| Redirection | Disable LPT port redirection | `fDisableLPT` | Computer GPO inspection |
| Redirection | Disable Plug and Play device redirection | `fDisablePNPRedir` | Computer GPO inspection |
| Redirection | Disable camera redirection | `fDisableCameraRedir` | Computer GPO inspection |
| Redirection | Disable microphone redirection | `fDisableAudioCapture` | Computer GPO inspection |
| Redirection | Disable audio/video playback redirection | `fDisableCam` | Computer GPO inspection |
| Redirection | Allow time-zone redirection | `fEnableTimeZoneRedirection` | Computer GPO inspection |
| Printer | Use Easy Print driver first | `UseUniversalPrinterDriverFirst` | Computer GPO inspection |
| Session | Idle session limit | `MaxIdleTime` | Local allowlisted DWORD |
| Session | Active session time limit | `MaxConnectionTime` | Local allowlisted DWORD |
| Session | Disconnected session time limit | `MaxDisconnectionTime` | Local allowlisted DWORD |
| Session | Automatic reconnection | `fDisableAutoReconnect` | Computer GPO inspection (inverted value) |
| Session | End sessions on time limit | `fResetBroken` | Computer GPO inspection; per-user policy may also exist |
| Transport | TCP/UDP transport policy | `SelectTransport` | Computer GPO inspection |
| Connection | RDP keep-alive enabled | `KeepAliveEnable` | Read-only local and policy diagnostic |
| Connection | RDP keep-alive interval | `KeepAliveInterval` | Read-only local and policy diagnostic |
| Security | Blank-password restriction (local accounts) | `LimitBlankPasswordUse` in **LSA** | Separate verified inline local security editor |

These values are intended for Windows 10/11 and corresponding modern Windows
Server versions. Some policies may not apply to a particular edition, SKU,
connection type or client. Any missing value is treated as unknown / not
configured, never as proof of an enabled service or feature.

## Blank-password interpretation

| LSA DWORD | UI | Meaning |
|---|---|---|
| `1` | Restriction ON | Local empty-password accounts cannot normally sign in over remote network services |
| `0` | Restriction OFF — high risk | This one restriction does not block remote empty-password sign-in |
| Missing, invalid or unreadable | Unknown | No local security edit is offered |

These are **local account** settings, not domain authentication settings.
Neither `0` nor `fPromptForPassword=0` proves that an actual RDP connection
will accept empty credentials. NLA, logon rights, account state, firewall and
other Windows policies can still prevent access. Microsoft recommends
restricting blank passwords to the local console.

## System Health integrity distinction

On the first explicit DLL Health inspection, the application records an
immutable **First Seen (Unverified)** reference in the current user's local
profile. This is useful for comparing future file versions and SHA-256 values,
including after a Windows Update. It is **not** proof that the DLL was
unmodified or signed by Microsoft. An operator-saved baseline is separate.
Neither is used to decide whether protected patching or Restore is permitted.

## Future candidates (not yet implemented)

- Read-only **effective Firewall rule** inspection (profile, port, address
  scope, GPO ownership and protocol) rather than a misleading enabled icon.
- An **RDP entitlement and logon-rights** inspector: local group membership,
  `SeRemoteInteractiveLogonRight` and deny rights; show only user-approved
  on-screen evidence, never transmit identities in anonymous reports.
- WMI/CIM-based **per-setting source** for audio, monitor, printer, color depth,
  and supported device redirection.
- **TLS certificate and expiry** diagnostics, with no automatic replacement.
- **H.264/AVC hardware encode**, visual experience and bandwidth policies,
  behind capability / OS checks.
- An authenticated read-only **listener check** for TCP/UDP and live session
  count; never assert successful external connectivity from a local socket.
- Security Policy RSoP `secedit`/MDM provenance for LSA settings with clear
  unknown results and zero automatic GPO edits.

## Microsoft references

- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions
- https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords-to-console-logon-only
- https://learn.microsoft.com/en-us/azure/virtual-desktop/configure-rdp-shortpath
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/terminal-services-cannot-restart-keep-alive-enabled
