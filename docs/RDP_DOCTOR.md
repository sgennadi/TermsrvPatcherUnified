# RDP Doctor — local, read-only diagnostics (Preview 1.0.6-preview.2)

RDP Doctor is inside **Advanced → Remote Desktop**. Select **Run RDP Doctor** for a
single scan of TermService, configuration, TCP listeners, Windows Firewall, LSA
rights, TLS certificate metadata, graphics policy and bounded RDP event metadata.
The scan **does not** modify Firewall settings, registry, services or system DLLs.

## Understanding the statuses

| Status | Meaning |
|---|---|
| **Verified locally** | A specific local fact was checked (for example a configured active port/rule match), **not** end-to-end RDP connectivity |
| **Observed locally** | A source was read and its contents observed; the effective remote result (e.g. token, TLS handshake, codec) has **not** been evaluated |
| **Attention** | Potential problem or security risk needing manual review, but not automatically proof of a blocked connection |
| **Blocker** | A concrete local blocker (such as a stopped service or absent listening socket) |
| **Unavailable** | Inspection failed or no usable source data was available |
| **Incomplete** | Some useful metadata exists, but a needed element or enumeration is missing |
| **Not tested** | Deliberately unperformed external TCP/TLS/authentication/interactive sign-in test |

The dashboard shows six compact counters: local blockers, attention, local evidence
(combining Verified/Observed locally), unavailable, incomplete, and not tested.
The exact status remains visible in every table row with a distinct background.
The safe local clipboard report never includes raw account names, Firewall rule
names, source IP address scopes, certificate subjects, event messages or paths.

## Windows Firewall diagnosis

The inspector first uses **HNetCfg.FwPolicy2** (read-only COM). It inspects
inbound **TCP** candidates only, including known RDP rule groups, TermService
rules and custom rules with **explicit local ports matching the configured
RDP TCP port**. It reads:

- The configured RDP port instead of blindly assuming 3389
- Current active Domain/Private/Public Firewall profiles and rule-profile intersection
- Per-rule Enabled and Allow/Block action
- Local port (including comma lists and numeric ranges) and remote address scope

An enabled matching Block candidate is **Attention**. Matching Allow rules
can be marked **Verified locally** *only for that specific rule/profile/port
metadata*, not for the effective Windows Filtering Platform decision, user
authentication, network routing, NLA, GPO precedence or third-party filtering.
A missing matching Allow candidate is Attention, **not** an assertion that
Windows definitely blocks RDP.

If COM is not available, the program tries the local read-only
`root/StandardCimv2:MSFT_NetFirewallRule` provider. This reports only
bounded RDP rule metadata; it does not join the separate port/address filters,
so it remains **Incomplete**. If CIM is also unavailable, a very limited
local registry snapshot is shown. Neither fallback is labelled as proof of
an effective firewall rule. The Technical evidence panel includes the
exception *type* from inaccessible sources, not credential or machine details.

No automatic action disables Windows Firewall, modifies an inbound rule,
restarts TermService, or opens an RDP port.

## Other checks

- **TermService / RDP enablement / listener / NLA:** verified local facts can
  be shown independently; external sign-in remains Not tested
- **Remote interactive logon rights:** successful LSA enumeration becomes
  Observed locally, not account authentication confirmation; nested group
  memberships and effective user tokens are not evaluated
- **RDP TLS certificate:** observed dates alone do not prove the active listener
  handshake, certificate chain trust or private-key ACLs
- **Graphics / codec:** registry values can be observed, but codec negotiation
  is not performed
- **Event logs:** sampled event records are local observations. No sampled
  errors does not prove connectivity; missing channels are Incomplete

## Verification and limitations

Synthetic tests check port matching, custom rules, profile mismatch, disabled
and UDP-only rules, potential Block precedence, partial source failure, and
the privacy boundary of copied reports. WPF offscreen tests check the expanded
status dashboard, color-coded rows and read-only details. Windows CI never
runs an external RDP sign-in, changes Firewall or system DLLs, or validates a
real Windows 11 RDP reconnection. Those require an authorized separate test
computer and recovery access.

## Microsoft references

- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule
- https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogreader
