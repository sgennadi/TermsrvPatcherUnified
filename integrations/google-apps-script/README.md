# Free diagnostic reports via Google Apps Script -> GitHub Issues

The owner supplied a Google Apps Script deployment URL, now embedded in the application. An operator-approved live submission was confirmed in public diagnostic Issue #46 and compatibility Issue #1 on 2026-11-11. Such receipts do not independently prove a working RDP session. It costs no monthly subscription within Google Apps Script's quota and requires no private VPS. It is nevertheless a *public, hosted HTTPS receiver*. The Formspree Free plan does **not** automatically forward messages to GitHub: its webhook integration is paid.

## What the repository owner configures ONCE

1. Create a Google account if needed and open https://script.google.com/home/start . Create a blank project named **TermsrvPatcherUnified Reports**. Keep its editor access private.
2. Go to GitHub Settings > Developer settings > Personal access tokens > Fine-grained tokens:
   https://github.com/settings/personal-access-tokens/new
   - Resource owner: \`sgennadi\`.
   - Repository access: **Only select repositories** > \`TermsrvPatcherUnified\`.
   - Repository permissions: **Issues: Read and write** (Metadata: read is automatically added).
   - Choose an expiration you can maintain; GitHub may limit allowed lifetimes.
   - Generate a token and copy it once. **Never place this token in GitHub source code, the EXE, chat or a URL.**
3. In Google Apps Script open **Project Settings (gear) > Script Properties > Add script property**:
   - Property: \`GITHUB_ISSUES_TOKEN\`
   - Value: the fine-grained GitHub token from Step 2.
4. Replace the default contents of \`Code.gs\` with this repository's [Code.gs](Code.gs), then **Save**.
5. Google Apps Script **Deploy > New deployment > Web app**:
   - Description: \`TermsrvPatcherUnified diagnostics\`.
   - **Execute as:** Me (the script owner).
   - **Who has access:** Anyone (anonymous, not "anyone with Google account").
   - Click **Deploy**, grant the required permissions for script execution and outbound HTTP, and copy the \`https://script.google.com/macros/s/.../exec\` URL.
   - Opening this URL with GET should show a small JSON status. **GET does not create an Issue**.
6. Provide the **\`.../exec\` deployment URL only** to the TermsrvPatcherUnified application maintainer for build-time configuration. The URL itself is public, not a secret. **Never send the GitHub token.**
7. After updating to the new Google-enabled Preview, send **one test report after explicit user confirmation**, then check:
   - https://github.com/sgennadi/TermsrvPatcherUnified/issues (a public diagnostic Issue).
   - https://github.com/sgennadi/TermsrvPatcherUnified/actions/workflows/diagnostic-observations.yml (the \`issues.opened\` collector).
   - https://github.com/sgennadi/TermsrvPatcherUnified/blob/main/data/diagnostic-observations.csv (an **unverified** observation row).

If GitHub Actions cannot commit CSV, check the workflow's \`contents: write\` permission and repository branch rules. Do **not** grant a broad GitHub PAT to the EXE, and do not change verified patch patterns automatically.

## Important boundaries and safety

- **This does not connect the existing Formspree submissions automatically.** Free Formspree has no included webhook/Google Sheets forwarding. The EXE must be updated to send directly to the new Apps Script endpoint. Previous Formspree integration is archived in docs/archive/legacy-formspree.md and is not compiled into the new EXE.
- Apps Script is an HTTPS receiver on Google's infrastructure, **not a server you host**, and can be used within the free quotas. Google can change quotas or limit deployments.
- **GitHub Issues in this repository are public.** The client must disclose this and show the exact typed payload and destination *before* its Send action. Anonymous to the app developer is not absolute anonymity to the transport providers.
- Manual reports require an exact preview and explicit Send confirmation. By default, nothing uploads automatically. Only after the administrator separately checks **Automatically send unified reports** and the initial two public receipts succeed, later newly successful protected Auto Reapply runs may submit the same bounded diagnostic and compatibility metadata silently. The setting is revocable from Simple or Advanced; opted-out DLL metadata is never sent.
- The anonymous endpoint has **no reliable caller authentication**. Any person who learns the URL can submit correctly shaped events. Strict schema validation, no free-form body, a 15-Issues-per-UTC-day global limit, a six-hour duplicate cache and a token limited to **Issues write on one repository** reduce but do not eliminate spam or abuse. Monitor Issues and disable the deployment if abused. Never rely on application-embedded API keys for security.
- If the token expires, replace the single \`GITHUB_ISSUES_TOKEN\` Script Property. No change to the EXE is required.
- A Google Apps Script ContentService JSON response is delivered through a redirect to \`script.googleusercontent.com\`. The updated .NET client must follow **only trusted Google redirect hosts** and check JSON \`ok === true\` and a valid GitHub Issue URL, not merely an HTTP 200 response.
- Google Apps Script normally returns HTTP 200 even if the response JSON is \`{"ok":false,...}\`; clients must parse the result.
- Do not add GitHub PATs to GitHub Actions Variables or Secrets for this particular bridge. The token exists **only** in the owner's Apps Script Script Properties.

## Existing parser integration

The web app maps exactly the allowed \`universal-diagnostics/v1\` Windows/DLL fields to the project's existing public Issue format:

- Title: \`[Diagnostics] TermsrvPatcherUnified <UUID prefix>\`
- Body: marker \`udx-report-id\`, optional compatibility observation marker, sixteen validated typed fields, and the exact required privacy footer.
- It then uses GitHub REST \`POST /repos/sgennadi/TermsrvPatcherUnified/issues\` with the server-side token.
- The existing \`diagnostic-observations.yml\` workflow parses those Issues into \`data/diagnostic-observations.csv\`, which is marked \`unverified\`. Unverified reports never become automatically trusted patch patterns.

The repository maintainer's assistant did not deploy the Google project or submit live public reports. The operator separately confirmed delivery to public Issues #46 and #1; automated CI tests remain synthetic/offline.

## Upgrade existing deployment for token-free fix reports (Stable 1.0.5)

The same public `/exec` endpoint now accepts two **strictly separated** typed JSON schemas. `universal-diagnostics/v1` still creates a public diagnostic Issue and populates unverified observations; `termsrv-compatibility/v1` creates a comment on the already-open public [Issue #1](https://github.com/sgennadi/TermsrvPatcherUnified/issues/1). The reply includes both `issue_url` and `comment_url`; the Windows client verifies the comment receipt before indicating success.

Owner: copy the updated [Code.gs](Code.gs) into your existing Google Apps Script project, click **Save**, then **Deploy > Manage deployments > Edit (pencil) > Version: New version > Deploy**. Do **not** create a separate deployment when retaining the current configured endpoint. The pre-existing owner-only `GITHUB_ISSUES_TOKEN` must remain in Script Properties with Issues write rights. No end user needs GitHub credentials. The gateway itself does not initiate unattended uploads or automatic retries. A Windows SYSTEM Auto Reapply worker can submit two typed records only after independently protected, endpoint-bound, operator-approved consent and verified Apply; no silent submission occurs by default. This repo's CI tests do not deploy Apps Script or create live reports.

The gateway accepts only complete original/patched SHA-256 and bounded edits; an offline report additionally requires CRC32/architecture. A 30-comment UTC-day limit, 6-hour event-id cache, strict metadata grammar and known Issue URL reduce abuse but do not authenticate the submitter. Every imported record remains **UNVERIFIED**; use it for diagnostics, never authorization, Microsoft provenance or automatic patch selection. Updating the embedded CSV index still requires publishing a new EXE.


## Diagnose partial delivery and verify the deployed gateway version

If a reviewed **Unified Apply report** creates a diagnostic Issue, but the DLL
compatibility comment is not confirmed, **do not interpret this as a full
success**. Keep the review window open and use **Retry DLL compatibility only**
after fixing the receiver; the already confirmed diagnostic Issue is not
resent during that same window session.

The repository version of `Code.gs` now exposes a **read-only** GET capability
response with `"gateway_schema_version":2` and
`"capabilities":["universal-diagnostics/v1","termsrv-compatibility/v1"]`.
Open the application's existing Google `.../exec` URL in a browser and check
that both schemas are listed. GET cannot create an Issue/comment and never
exposes the server-side GitHub token. If these fields are absent, the live
deployment is older than the checked-in script. In Apps Script: replace
`Code.gs` with the latest repository file, save it, and choose
**Deploy > Manage deployments > Edit (pencil) > Version: New version > Deploy**.
Retain the same URL, web app access **Anyone**, and **Execute as Me**.

If the GET capabilities are correct but compatibility still fails, inspect the
exact error displayed in the revised report window: `invalid_evidence` means
the receiver rejected the typed payload; `github_not_confirmed` means the
GitHub comment write failed (check Script Properties for
`GITHUB_ISSUES_TOKEN` and repository Issues:write permission). Do not paste
the token or confidential logs into a public Issue or chat. The app closes the
report window **only after all required GitHub receipts** and never grants
unattended reporting consent on partial delivery. Reopening a different EXE
does not automatically recover in-memory partial receipt state.
