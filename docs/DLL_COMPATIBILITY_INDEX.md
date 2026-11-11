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

Copied evidence normalizes unsafe registry and PE version labels to prevent local paths and identities from leaking into exported reports.

## Unified Apply report and future silent Auto Reapply (1.0.5 candidate)

After a verified interactive Apply, one report window combines two clearly separated read-only sections: strict `universal-diagnostics/v1` Windows/DLL diagnostics (a public GitHub Issue) and strict `termsrv-compatibility/v1` change evidence (a comment on Issue #1). One **Review and send** confirmation displays the complete contents and receiver before the program submits either record; both acknowledgements are checked. An offline DLL copy retains its separate, compatibility-only observation and never enables automatic reporting. All reports are unverified observations, not working-RDP evidence.

An unchecked-by-default **Automatically send unified reports after future successful Auto Reapply runs** choice is shown only in the Apply report window. Consent is persisted machine-wide in an administrator/SYSTEM-only directory **after both manually approved records are confirmed** and bound to the exact configured Google receiver. An enabled protected Windows Update / boot / daily Auto Reapply SYSTEM task checks this consent and, only after a newly applied, exact automatic signature passes SHA-256 verification and durable state recording, silently sends the same two typed sections. There is no UI, queue or automatic retry, and any reporting failure never changes Apply success or rollback. No reports for AlreadyPatched, failed, uncertain, skipped, manual or offline operations. Simple and Advanced expose **Stop automatic reports** to revoke consent without disabling patch maintenance.

## Collecting reports for future builds (1.0.5 candidate)

After a **completed, locally verified** console Apply, or separately after a saved **offline DLL copy**, the optional report window shows the exact JSON. **Review and send** asks for a second explicit confirmation with destination and complete payload. The app uses the already configured Google Apps Script HTTPS receiver and **never requires a GitHub token on the client**. Send is disabled if the approved endpoint is unavailable. Declining changes nothing and sends nothing.

The new `termsrv-compatibility/v1` envelope has exactly six fields: `schema`, random event `id`, `timestamp_utc`, `project`, `kind` and a strictly formatted `body`. The only accepted bodies are `termsrv-success/v2` and `termsrv-offline/v1`, each retaining the existing parser's exact schema. The gateway validates full byte-range and SHA/CRC data and forwards a public comment to GitHub Issue #1 using a server-side token. Only a validated GitHub comment receipt counts as delivery. An existing GitHub Actions collector writes to separate CSVs. **Both categories stay UNVERIFIED**; an offline observation is not a successful Windows Apply or a functional RDP connection.

**Deployment:** the source change on GitHub does not update a running Apps Script deployment. The owner must save the new `integrations/google-apps-script/Code.gs` and choose **Deploy > Manage deployments > Edit > New version > Deploy** for the existing endpoint. The current deployed endpoint may still reject this new report schema until that is done. No live report or downstream CSV aggregation was performed by automated tests.

A Session 0 Apply performed through the independent scheduled executor is not yet offered this new interactive confirmation automatically; this feature covers GUI-confirmed local-console Apply and offline copy only. The embedded index still refreshes only in a new EXE build.
