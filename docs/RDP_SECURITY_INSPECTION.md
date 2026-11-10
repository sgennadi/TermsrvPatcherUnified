# RDP extended diagnostics (1.0.3)

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
