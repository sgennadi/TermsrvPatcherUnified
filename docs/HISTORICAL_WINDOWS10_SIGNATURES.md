# Historical Windows 10 pattern references — manual-only

**Source:** [MySysAdminTips, Multiple RDP (Remote Desktop) sessions in Windows 10](https://www.mysysadmintips.com/multiple-rdp-remote-desktop-sessions-in-windows-10/). These are functional HEX examples from the linked article, not independently verified binary evidence.

The six added signature pairs are recorded only in `Patterns/LegacyUserPatterns.MANUAL.txt` and are **not embedded** into the automatic catalog, not assumed valid from a reported Windows version, and not authorized by these notes for protected system writes. Read-only matching, PE executable range checks, backups, rollback and licensing review still apply. No original Microsoft DLL was downloaded from the third-party page.

| Reported Windows 10 DLL version | Historical Find (12 bytes) |
| --- | --- |
| 10.0.19041.3570 | `39 81 3C 06 00 00 0F 84 F7 40 01 00` |
| 10.0.19041.3271 | `39 81 3C 06 00 00 0F 84 E7 43 01 00` |
| 10.0.17763.1 | `39 81 3C 06 00 00 0F 84 7F 2C 01 00` |
| 10.0.15063.0 | `39 81 3C 06 00 00 0F 84 53 71 02 00` |
| 10.0.10586.0 | `39 81 3C 06 00 00 0F 84 3F 42 02 00` |
| 10.0.10240.16384 | `39 81 3C 06 00 00 0F 84 73 42 02 00` |

**Shared historical Replace** (12 bytes): `B8 00 01 00 00 89 81 38 06 00 00 90`. The article also repeats previously cataloged examples (e.g. Windows 10 22H2 / 19041.2075 and Windows 10 1809 / 17763.437), which were not added as duplicates.

## Scope of evidence

- This Windows 10-only reference is **not** evidence for Windows 11 25H2 or 26H2, or Windows Server 2025.
- On the GitHub-hosted Windows Server 2025 runner, the authentic `termsrv.dll` 10.0.26100.32684 matched the existing **13-byte Windows 11 24H2-family** Find once (offset `0x0009C43F`); neither the upstream alternative 12-byte hotpatch Find nor the 19-byte 25H2/26H2 Find matched. [Read-only QA run](https://github.com/sgennadi/TermsrvPatcherUnified/actions/runs/42659665234).
- The original operator-provided Windows 11 26H2 report for DLL 10.0.26100.8115 showed an independent **19-byte** original match at `0x000A6896`; CI reproduced it with synthetic bytes, *not* a copy of that DLL. Its 12-byte suffix appears at `0x000A689D` only as a consequence of the exact 19-byte original match, not as an independently verified live-memory patch.
- The separate [haojiezhe12345 hotpatch source](https://github.com/haojiezhe12345/termsrv-multiuser-patcher/blob/main/termsrv_hotpatch.py) uses a different replacement strategy (12-byte `75` to `EB` jump change). That source does not validate the 19-byte replacement choice, and no memory-writing feature was enabled.
