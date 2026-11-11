# RDP extended diagnostics (1.0.3)

## Preview 1.0.6-preview.2: Firewall read-only evidence and safer interpretation

The unified RDP Doctor now checks inbound TCP candidates against the **actual
configured RDP port**, active profile, Allow/Block action and rule state.
Classic Firewall COM is tried first; if unavailable, **limited** local CIM
then registry evidence is displayed with explicit "Incomplete/Unavailable"
status. Fallback output is never presented as effective Firewall authorization.
No rules, service states, credentials or system DLLs are modified.

See [RDP Doctor details](RDP_DOCTOR.md) for all statuses, limitations and
synthetic QA. An observed matching Allow rule proves only the local rule
metadata; it does not prove remote connection or RDS licensing.


Four new read-only panels are available in **Remote Desktop > Connection diagnostics**.

| Panel | Source and meaning | Not proved |
|---|---|---|
| Firewall | `HNetCfg.FwPolicy2` COM enumeration of built-in RDP inbound rules; enabled state, action, TCP/UDP ports, applied profile mask, remote address scope | Actual effective firewall access, third-party filters, upstream firewall/NAT or off-machine reachability |
| Logon rights | Local LSA `LsaEnumerateAccountsWithUserRight` for `SeRemoteInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight`; account and group display **only in the local UI** | Effective group token and nested membership, exact winning domain GPO/MDM, actual credentials or successful RDP login |
| RDP certificate | `Win32_TSGeneralSetting.SSLCertificateSHA1Hash`, listener binding fallback, LocalMachine Remote Desktop/My certificate stores, validity dates and subject | Remote TLS handshake, full certificate-chain trust, TermService private-key ACL, client pinning |
| Graphics | Computer RDP policy values in `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`: hardware GPU, H.264/AVC preference, AVC 444 and WDDM | Actual GPU usage, negotiated display codec, RDP client support, network bandwidth |

These inspections do not change any RDP configuration, user account, group,
GPO, firewall rule, certificate, file, or service. All unknown/inaccessible
readings remain clearly labelled. No account names, group memberships or
certificate subjects are included in anonymous diagnostic submissions.

**Interpreting the results:** A firewall Allow rule does not establish
reachability. A valid-looking certificate may not be trusted or may not be
the one actually presented over the network. Local policy enumerations
cannot resolve all domain and MDM precedence. If independent verification
is unavailable, the tool reports Unknown instead of Enabled.

**Safety:** inspect a production RDP host with independent console recovery.
Never lower NLA or encryption just because this read-only report is incomplete.

### References

- https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
- https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver

## Unified Doctor UI (1.0.5 candidate)

Run **Advanced > Remote Desktop > Run RDP Doctor** once, then expand **RDP Doctor > Technical evidence** for detailed Firewall, local LSA logon rights, TLS and graphics metadata. This is the same read-only security inspection the RDP Doctor summary uses. Raw local account and certificate data stay visible only in the GUI; they are never included in the sanitized copied report.
