# DLL compatibility evidence index — 1.0.5 candidate

This is a **read-only, offline** evidence panel inside **Advanced > System Health**.

Press **Check DLL health** to refresh the SHA-256/version comparison and the compatibility index. Use **Copy evidence** for a local, bounded report that excludes the local DLL path, user name, computer name, IP addresses, Windows event messages and credentials. Nothing is transmitted.

## Evidence levels

| Item | Meaning |
|---|---|
| Installed DLL snapshot | Locally observed version, SHA-256 and Windows release/build |
| First seen | First locally stored observation, explicitly **unverified** |
| Operator baseline | User-selected comparison reference, **not** authenticated provenance |
| Embedded signature | Local exact original/replacement pattern matching, SHA/version-bound; not Microsoft original provenance or permission to Apply |
| Anonymous diagnostic observations | Bundled opt-in diagnostic metadata with matching **exact** DLL version and SHA-256; receipt is not success |
| Self-reported successful fixes | Bundled opt-in metadata that names an exact pre-change or post-change SHA-256; **unverified self-report**, not end-to-end confirmation |
| Authentic Microsoft original | **Not verified**: no Microsoft baseline catalog is bundled, and this UI does not validate signing chains or component-store identity |
| Automatic Apply eligibility | **Separate check**, never affected by this index |

Anonymous observations and successful-fix reports are different data sources, but **both are unverified**. Report counts are displayed only for exact DLL version+SHA matches. Windows release/build/UBR matching diagnostic observations are counted separately; a version-only match is never presented as an exact match.

## Data and trust boundary

The application embeds fixed snapshots of:
- data/diagnostic-observations.csv
- data/successful-fixes.csv

The index does not poll GitHub or download dynamic pattern catalogs. CSV validation is bounded (headers, column counts, sizes, version and SHA formats, report counts). Missing, malformed or unexpectedly large sources are **Unavailable**, never "verified", "compatible" or "no match". A new app build is needed to refresh embedded snapshots.

The existing **PatchCatalog**, protected Apply/Restore, manual patterns, automatic signature eligibility, System32 backups, integrity journal, NSudo authorization and auto-reapply code are unchanged. Neither the index nor a matching report can authorize changes to a Windows system DLL or licensing features.

## QA

Tests cover exact SHA/version matching, mismatch, self-reports and diagnostic reports kept unverified, first-seen limitations, invalid/missing CSV, invalid report count and path-free copy output. The Windows CI gate includes the new synthetic QA command and WPF offscreen control existence. Actual Windows 11 RDP connections, code signing/trust, and physical 200% scaling still require independent testing.
