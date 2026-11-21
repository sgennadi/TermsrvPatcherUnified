# Free GitHub Secrets signing — provisioning guide

This project supports a **planned** free self-signed Authenticode signing identity. No key has been provisioned yet, and release publishing and the updater remain disabled.

## Storage

- GitHub repository **Settings > Environments > New environment**: `release-signing`.
- Environment secrets: `TPU_SIGNING_PFX_BASE64` (base64-encoded PFX) and `TPU_SIGNING_PFX_PASSWORD` (strong, independent password).
- Repository variable: `TPU_SIGNER_SPKI_SHA256` (hex SHA-256 of certificate's SubjectPublicKeyInfo).
- Configure environment protection: restrict deployment branches to protected `main`; require reviewers **if your GitHub plan/repository supports it**. GitHub Secrets are accessible to jobs allowed to use that environment; a malicious workflow in main could exfiltrate the private key. The secrets are not a hardware-backed key vault.

## Provision without retaining the private key on a personal PC

Create the certificate and PFX inside a short-lived, private GitHub-hosted development environment (for example GitHub Codespaces). In that environment, use OpenSSL to generate a 3072-bit RSA key and a self-signed certificate with `extendedKeyUsage=codeSigning`, package them as PKCS#12, and calculate SPKI SHA-256. Use `gh secret set --env release-signing TPU_SIGNING_PFX_BASE64 --repo sgennadi/TermsrvPatcherUnified` to upload PFX base64 via standard input; similarly set the password and `gh variable set TPU_SIGNER_SPKI_SHA256`. Ensure `gh` is authenticated with permission to manage repository environments/secrets/variables. Delete the temporary development environment and its storage after verification. Never print or commit PFX, private key, password, or base64 to logs or artifacts.

**Note:** A temporary environment still handles the private key in plaintext while generating it. GitHub environment secrets do not eliminate the risk of repository/workflow compromise. Codespaces may have usage limits or charges outside free quotas.

## Required security work before enabling release

1. Test signing with `signtool` on a Windows runner; verify digest and expected SPKI pin independently.
2. Update `Core/ReleaseSignatureVerifier.cs` to validate a pinned self-signed signer with an explicit isolated trust policy; current WinVerifyTrust requires Windows trust and will reject an untrusted self-signed certificate. Never silently accept an arbitrary self-signed certificate.
3. Verify the *same* Authenticode signature that was validated by the OS and the pin; guard against multiple signatures and file swaps.
4. Embed the pinned public key in an independently reviewed bootstrap release. Never load a pin from the release being verified.
5. Only then re-enable release workflows and updater, with protected main and restricted signing environment. Existing unsigned installations require a deliberate manual bootstrap.

The deployed Google Apps Script and existing report URLs are unaffected.
