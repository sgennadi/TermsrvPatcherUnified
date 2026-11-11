# RDP Doctor — 1.0.4

RDP Doctor is a **read-only, local** diagnostic section in **Advanced > Remote Desktop**. It collects a bounded evidence snapshot and shows a conservative assessment, prioritized root-cause clues, and safe next steps.

## Run

Open **Advanced > Remote Desktop**, then select **Run RDP Doctor**. The header displays the number of local blockers, warnings and unverified areas. The grid displays the check, status, evidence and recommendation; the last 24-hour event table contains only UTC time, channel, event ID and numeric-level-derived severity.

**Copy safe report** copies summarized evidence and sanitized event metadata to your clipboard, never sending it anywhere. Expand **Technical evidence** inside RDP Doctor to see detailed Firewall, LSA logon rights, TLS certificate and graphics metadata. Both panes are populated from one read-only scan. Local identity and certificate details are never included in the copied report. Nothing modifies Windows.

## Checks

| Check | Source | Interpretation |
|---|---|---|
| Service | Service Control Manager / TermService | Stopped/Paused is a local blocker; Running is not a connection guarantee |
| Local RDP policy | Terminal Server registry and Policies registry | Disabled and contradictory values are shown; missing values are Unknown |
| TCP listener | RDP-Tcp configured PortNumber and IPGlobalProperties.GetActiveTcpListeners | No local socket is a local blocker; loopback-only is a warning; listening does not prove ownership or external reachability |
| NLA | RDP-Tcp UserAuthentication and matching policy | Not required is a security warning; missing is Unknown |
| Policy conflicts | Read-only local/policy comparison | Detects mismatched or invalid values, not full winning RSoP/MDM |
| Blank-password restriction | LSA LimitBlankPasswordUse | OFF is a security warning; ON is a local configuration observation; no remote authentication test |
| Firewall | Existing HNetCfg.FwPolicy2 read-only RDP rule metadata | No built-in group is a warning; even Allow cannot establish effective reachability |
| Logon rights | LSA enumerated Allow/Deny user-right assignments | Nested membership and actual token not computed; status remains Unknown |
| TLS | RDP binding and certificate store metadata | Invalid validity dates flagged; TLS handshake/trust not verified |
| Graphics | GPU, AVC/H.264/WDDM RDP GPO registry | Informational only; codec negotiation not detected |
| Event logs | LocalSessionManager, RemoteConnectionManager, RdpCoreTS | 24-hour, max 45 records/channel and 120 total; errors are correlation clues, not proof of a root cause |
| External client | Not probed by this version | Always Unverified; test from an independently authorized machine |

## Security and privacy

- **No writes** to termsrv.dll, the registry, GPO/MDM, Firewall, certificates, event logs, sessions, Windows services or Scheduled Tasks.
- No remote hosts are contacted; there is **no** automatic RDP sign-in or credential validation.
- Event messages, XML event properties, usernames, SIDs, addresses, machine names and certificate subjects are **not copied into RDP Doctor reports**. Only event channel, time, ID and severity metadata.
- A missing or denied probe is **Unverified**, never OK. Local TCP listening is a useful clue but not proof of external access or Microsoft RDS licensing entitlement.
- Event access may depend on permissions and OS SKU; unavailable channels are reported rather than skipped silently.
- For production changes involving TermService, test only from an independent console or hypervisor, with a verified backup and an appropriate Windows license.

## Validation

Synthetic tests verify blocked service, disabled policy, absent/loopback/all-interface TCP listeners, Unknown firewall/event channels, NLA warnings, and that the verdict cannot claim verified remote reachability. WPF offscreen smoke checks the single Remote Desktop tab, collapsed RDP Doctor panel and its read-only grids. GitHub CI does **not** exercise live Windows 11 RDP authentication, firewall reachability from another host or a real production failure.

Suggested future expansion: explicit operator-started **remote connectivity probe** from a separate authorized machine, and correlated client/server event timing (without collecting credentials). Do not enable automatic service restart or security downgrade as a troubleshooting shortcut.

## Microsoft references

- https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader
- https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ipglobalproperties.getactivetcplisteners
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-cannot-connect-remote-computer
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2

## Unified workspace (1.0.5 candidate)

There is no separate RDP Doctor tab or second Inspect four areas button. The single **Run RDP Doctor** action refreshes local configuration, security evidence and recent event metadata together. The prioritized findings and sanitized report remain visible in RDP Doctor; detailed security text stays local in its collapsed Technical evidence section. This is a UI/inspection consolidation only; no change to protected DLL operations.
