# Reporting without a self-hosted HTTPS receiver

Preview.26 adds direct, memory-only Formspree reporting without a mandatory local save. Windows CI uses mocked provider requests; live OAuth authorization and Windows scheduled-task permissions still require independent acceptance tests.

## Operating modes

**Formspree (no GitHub sign-in).** An administrator registers the form once; the form ID is compiled into the EXE and never typed by end users. Click Send report to prepare the metadata entirely in memory and review the *exact JSON* to be submitted to `https://formspree.io/f/FORM_ID`. It POSTs only canonical typed v1 metadata (including optional Windows build / DLL version / SHA-256 if explicitly selected), never free-text descriptions, raw logs, credentials, private paths, or native DLL bytes. The form submission may process the user's IP address. Successful Formspree receipt is shown in the UI; a local report/receipt is not required or fabricated. No GitHub Issue URL is created. **Formspree does not automatically populate `data/diagnostic-observations.csv`**. Configure retention and filtering in the Formspree dashboard. An active Formspree form is required; this build embeds the operator-provided public form ID `mvkkernb`. Formspree may reject submissions or impose plan limits.

**GitHub browser Device Flow (no PAT entry).** Register a GitHub OAuth App under an administrator-controlled account and enable Device Flow in its settings. The administrator embeds the OAuth App **Client ID** at build time; the end user clicks Connect GitHub, and enter the displayed code at `https://github.com/login/device`. Once authorization completes, the app retains the OAuth access token in memory for the dialog session only; no client secret, GitHub token or refresh token is stored. After saving/reviewing, select Publish via GitHub: the existing pinned Issue publisher sends the reviewed Markdown directly to `sgennadi/TermsrvPatcherUnified`. The public Issue becomes visible to everyone. A valid issue receipt is required before local delivery is acknowledged. A user must possess GitHub Issue creation rights for the repository. Device Flow is **not anonymous**, and OAuth scope `public_repo` is broader than issue-only permissions: the OAuth App can access public repository code. GitHub recommends code+PKCE for some native apps and GitHub Apps for finer-grained rights; this option is a conscious compatibility tradeoff. See [GitHub OAuth device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) and [OAuth scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

**Advanced PAT / self-hosted relay.** Existing manual PAT publication remains available behind the Advanced expander; existing HTTPS relay remains optional and is disabled without a trusted endpoint.

## One-time administrator setup — both IDs embedded in the EXE

The end user **does not install a script, create a config file, enter a Formspree form ID or enter a GitHub OAuth Client ID**. Neither `%PROGRAMDATA%\TermsrvPatcherUnified\reporting.json` nor environment variables are read by the application.

**Formspree is preconfigured in the source:** `config/reporting-defaults.json` contains the public form ID `mvkkernb`, corresponding to `https://formspree.io/f/mvkkernb`. GitHub Actions automatically embeds this into the EXE even if no repository variable is configured. The ID is not a secret. **The endpoint was supplied by the operator; the operator has reported receiving a message in Formspree. Automated CI still uses simulated HTTP.**

**Administrator setup, once (before new builds):**

1. **Formspree is already set to `mvkkernb`**; no additional form setup is needed unless you want a different destination. Verify the form is active in your Formspree account before using real reporting.
2. Register a trusted GitHub OAuth App in [GitHub Developer Settings](https://github.com/settings/developers), enable **Device Flow**, and copy its public **Client ID**. **Do not embed a client secret or PAT.** OAuth scope `public_repo` is broader than Issues-only access.
3. On the administrator's Windows machine install/sign into GitHub CLI (`gh auth login`) with permission to manage repository Actions Variables. In the checkout of this repository run **once**:

```powershell
pwsh -NoProfile -File .\scripts\Configure-Reporting.ps1
```

The optional interactive script uses `mvkkernb` as its default Formspree ID and asks for an optional GitHub OAuth Client ID. It validates the IDs and saves them as GitHub repository **Variables** (not Secrets). **You do not have to run it for Formspree**; normal GitHub Actions builds use the checked-in default automatically. Future `windows-ci.yml` and `release-preview.yml` builds automatically regenerate the local `.build/reporting.json`, embed it into the one-file EXE as resource `TermsrvPatcherUnified.ReportingProviders` and do not package any `*.json` or `*.ps1` sidecar.

If the administrator already has `%PROGRAMDATA%\TermsrvPatcherUnified\reporting.json` on the **build computer**, run the same script with `-ImportProgramData` to import its two IDs once and store them as GitHub Variables. The installed application will never read that file.

For **local-only builds**, pass `-LocalOnly`; for CI use `-FromEnvironment`, which never prompts, never connects to GitHub and falls back to `config/reporting-defaults.json` when an Actions Variable is absent. A nonempty repository variable overrides its corresponding default; GitHub OAuth remains disabled if no Client ID is provided. To reconfigure the published application, update the repository variables and rebuild the EXE. Updating the client EXE then distributes the new public IDs without per-PC setup.

**Important:** An OAuth Client ID does not sign users in automatically: GitHub always requires a browser authorization step. The Formspree method needs no account or setup on client PCs, but sending a report still requires an explicit user review and confirmation. A live Formspree form and GitHub OAuth App must actually exist; the script does not create third-party accounts or registrations.

## Safe delivery protocol


1. Prepare a sanitized universal diagnostic event **in memory** for Formspree. Windows build / DLL SHA-256 is selected by default, with an opt-out checkbox; a local copy is optional.
2. Select a provider. Review the **exact outgoing report** and pinned destination in a second confirmation.
3. Send once, with bounded HTTPS responses and no HTTP redirects or cookies. Formspree requires explicit successful JSON acknowledgement. GitHub requires HTTP 201 and an Issue URL for this repository.
4. Show a provider-specific acknowledgement. Only optional local/GitHub workflows write queue receipts; direct Formspree does not need a local record. No automatic retry after uncertain delivery.
5. All community diagnostic observations remain **unverified**. Neither this module nor an Issue/CSV event ever authorizes binary patching or modifies the active patch catalog.

## Tests and limits

Windows Actions includes synthetic HTTP tests for both providers, malformed report exclusion, OAuth request scopes and token handling, and Formspree-specific local receipts. They do **not** prove Formspree form availability, a valid OAuth client ID, successful external login, actual public Issue posting, or production readiness.

Formspree and GitHub are third-party services with separate terms, retention and abuse controls. User privacy and IP-level anonymity cannot be guaranteed. Do not enable unattended or silent submission.
