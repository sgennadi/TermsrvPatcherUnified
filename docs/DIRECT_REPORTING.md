# Reporting without a self-hosted HTTPS receiver

Draft feature in PR #27; release and live provider acceptance have not yet been completed.

## Operating modes

**Formspree (no GitHub sign-in).** An operator first creates/owns a Formspree form and enters its public form ID in Diagnostics. After saving and reviewing a diagnostic, the app offers the *exact JSON* to be submitted to `https://formspree.io/f/FORM_ID`. It POSTs only canonical typed v1 metadata (including optional Windows build / DLL version / SHA-256 if explicitly selected), never free-text descriptions, raw logs, credentials, private paths, or native DLL bytes. The form submission may process the user's IP address. Successful receipt is stored locally with provider `formspree`; no GitHub Issue URL is fabricated. **Formspree does not automatically populate `data/diagnostic-observations.csv`**. Configure retention and filtering in the Formspree dashboard. Formspree service account and active form are required; no form ID is embedded. Formspree may reject submissions or impose plan limits.

**GitHub browser Device Flow (no PAT entry).** Register a GitHub OAuth App under an administrator-controlled account and enable Device Flow in its settings. Enter the OAuth App **client ID**, click Connect GitHub, and enter the displayed code at `https://github.com/login/device`. Once authorization completes, the app retains the OAuth access token in memory for the dialog session only; no client secret, GitHub token or refresh token is stored. After saving/reviewing, select Publish via GitHub: the existing pinned Issue publisher sends the reviewed Markdown directly to `sgennadi/TermsrvPatcherUnified`. The public Issue becomes visible to everyone. A valid issue receipt is required before local delivery is acknowledged. A user must possess GitHub Issue creation rights for the repository. Device Flow is **not anonymous**, and OAuth scope `public_repo` is broader than issue-only permissions: the OAuth App can access public repository code. GitHub recommends code+PKCE for some native apps and GitHub Apps for finer-grained rights; this option is a conscious compatibility tradeoff. See [GitHub OAuth device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) and [OAuth scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

**Advanced PAT / self-hosted relay.** Existing manual PAT publication remains available behind the Advanced expander; existing HTTPS relay remains optional and is disabled without a trusted endpoint.

## Configuration

To prefill public (nonsecret) provider identifiers for all users, an administrator may create the UTF-8 JSON file:

`%PROGRAMDATA%\TermsrvPatcherUnified\reporting.json`

```json
{
  "formspree_form_id": "REPLACE_WITH_YOUR_FORM_ID",
  "github_oauth_client_id": "REPLACE_WITH_YOUR_OAUTH_APP_CLIENT_ID"
}
```

The above strings are placeholders, **not valid working credentials**. The file may omit either field. User-entered values last only for the dialog session. The app refuses unrelated JSON keys, control characters, unsafe URLs and malformed provider IDs. It never writes these settings itself.

## Safe delivery protocol

1. Write a **local** sanitized universal diagnostic event. Windows build / DLL SHA-256 is opted in separately (default OFF).
2. Select a provider. Review the **exact outgoing report** and pinned destination in a second confirmation.
3. Send once, with bounded HTTPS responses and no HTTP redirects or cookies. Formspree requires explicit successful JSON acknowledgement. GitHub requires HTTP 201 and an Issue URL for this repository.
4. Store a provider-specific acknowledgement. No automatic retry after uncertain delivery; the operator must verify the provider dashboard/Issues first.
5. All community diagnostic observations remain **unverified**. Neither this module nor an Issue/CSV event ever authorizes binary patching or modifies the active patch catalog.

## Tests and limits

Windows Actions includes synthetic HTTP tests for both providers, malformed report exclusion, OAuth request scopes and token handling, and Formspree-specific local receipts. They do **not** prove Formspree form availability, a valid OAuth client ID, successful external login, actual public Issue posting, or production readiness.

Formspree and GitHub are third-party services with separate terms, retention and abuse controls. User privacy and IP-level anonymity cannot be guaranteed. Do not enable unattended or silent submission.
