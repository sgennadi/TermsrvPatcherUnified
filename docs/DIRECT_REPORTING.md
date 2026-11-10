# Diagnostics via Google Apps Script — user-approved, free-tier-compatible

**Active destination (embedded in the EXE):** `https://script.google.com/macros/s/AKfycbyV-tq5tMa08XaEmgo6-vpHD6ISQGOci32oPjy5ELm2pHUAud_Wn5j5YjVV0kcc6o62/exec`.

End users do **not** enter an endpoint, GitHub account, access token or local configuration file. The built-in **Send report** button prepares sanitized typed Windows and `termsrv.dll` metadata entirely in memory. Before network activity, the dialog displays the **exact JSON**, destination and the fact that the resulting GitHub Issue will be public. Only explicit confirmation sends one POST. No automatic retries, unattended telemetry or local report save are required.

Google Apps Script (running under the owner's Google account) validates the event, uses a private `GITHUB_ISSUES_TOKEN` stored in **Script Properties** to create an Issue in `sgennadi/TermsrvPatcherUnified`, and replies with `{"ok":true,"issue_url":"https://github.com/sgennadi/TermsrvPatcherUnified/issues/N"}`. Google ContentService can redirect the response to `script.googleusercontent.com`; the client only follows the expected Google host and validates the final Issue URL for this repository. Other responses are **not** treated as successful delivery.

GitHub Actions workflow `diagnostic-observations.yml` imports correctly formatted Issues into `data/diagnostic-observations.csv` as `unverified`. This data must never automatically authorize patching or populate the trusted signature database.

## Owner setup

The deployed Google URL was supplied by the repository owner. The GitHub token is **never** embedded in the executable, source, or ChatGPT conversation. Owner-side steps are documented in [the Google gateway setup guide](../integrations/google-apps-script/README.md). The token must be restricted to the target repository's **Issues: write** permission. The app builds embed the public Google URL through `config/reporting-defaults.json` and `scripts/Configure-Reporting.ps1`. Set the optional GitHub Actions Variable `TPU_GOOGLE_APPS_SCRIPT_URL` only when switching deployments.

**Important:** An existing deployed Apps Script might be running an older revision than the repository's `Code.gs`. This answer does not claim that the live deployment accepts requests; only synthetic fake-HTTP tests can run safely without deliberately creating a public Issue.

## Safety and limits

- GitHub Issues are public. Windows build, DLL version, SHA-256 and other strictly typed fields become visible to everyone who can view the repository. The user always sees the fields and consents before sending. Google may process the caller's IP address.
- The Apps Script web app is accessible to anyone, with no strong client authentication. Rate limits, strict schema validation and duplicate detection reduce abuse but do not eliminate it.
- The existing deployed Apps Script compatibility v1 requires all five optional Windows/DLL evidence fields for Issue creation. If **Include Windows build, termsrv.dll version and SHA-256** is unchecked, the main Google Send option is disabled rather than silently substituting data or uploading less than the server accepts. Local-only reports remain available in Advanced.
- Use GitHub Issues and the `diagnostic-observations.csv` to review submission activity. The program never asserts success from an HTTP 200 alone; only a validated GitHub Issue receipt counts.
- The former public Formspree ID is retained in [legacy archive](archive/legacy-formspree.md) but no Formspree code or endpoint is included in the EXE.
