# Free diagnostic reports via Google Apps Script -> GitHub Issues

This is an **optional, not-yet-deployed integration**. It costs no monthly subscription within Google Apps Script's quota and requires no private VPS. It is nevertheless a *public, hosted HTTPS receiver*. The Formspree Free plan does **not** automatically forward messages to GitHub: its webhook integration is paid.

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
7. Once the application has been updated to use this optional endpoint, send **one test report after explicit user confirmation**, then check:
   - https://github.com/sgennadi/TermsrvPatcherUnified/issues (a public diagnostic Issue).
   - https://github.com/sgennadi/TermsrvPatcherUnified/actions/workflows/diagnostic-observations.yml (the \`issues.opened\` collector).
   - https://github.com/sgennadi/TermsrvPatcherUnified/blob/main/data/diagnostic-observations.csv (an **unverified** observation row).

If GitHub Actions cannot commit CSV, check the workflow's \`contents: write\` permission and repository branch rules. Do **not** grant a broad GitHub PAT to the EXE, and do not change verified patch patterns automatically.

## Important boundaries and safety

- **This does not connect the existing Formspree submissions automatically.** Free Formspree has no included webhook/Google Sheets forwarding. The EXE must be updated to send directly to the new Apps Script endpoint. Until such an EXE is released, reporting continues to Formspree.
- Apps Script is an HTTPS receiver on Google's infrastructure, **not a server you host**, and can be used within the free quotas. Google can change quotas or limit deployments.
- **GitHub Issues in this repository are public.** The client must disclose this and show the exact typed payload and destination *before* its Send action. Anonymous to the app developer is not absolute anonymity to the transport providers.
- No automatic uploads after Apply. User consent, destination preview and explicit send remain mandatory. Opted-out DLL metadata is not forwarded into the compatibility CSV.
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

All code here is prepared for human deployment and local testing; Google project deployment, real requests and end-to-end receipt confirmation have **not** been performed by the repository maintainer's assistant.
