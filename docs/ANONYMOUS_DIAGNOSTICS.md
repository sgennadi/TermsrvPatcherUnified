# Anonymous diagnostics, Windows build and DLL SHA-256 — development branch

This project vendors the canonical .NET relay client maintained in
[UniversalDiagnocticsModule](https://github.com/sgennadi/UniversalDiagnocticsModule)
(`embedded/dotnet/UniversalDiagnosticsRelayClient.cs`, in the draft
`feature/universal-anonymous-relay-v1` branch). It does not contain a public
diagnostics receiver or embedded GitHub credentials.

**Current status:** the reference Cloudflare Worker relay is not deployed or
production-certified. The button remains disabled without a configured
trusted HTTPS endpoint. No live delivery is claimed by CI.

## Explicit approval and data minimization

First choose **Review and save locally** in Diagnostics; this writes an event to
the existing `universal-diagnostics/v1` queue. Then **Send anonymously**
presents the exact outgoing JSON in a separate confirmation. It may send only
these event properties:

- `schema`, `id`, `timestamp_utc`, `project`, `component`,
  `error_type`, `code`, `level`, `version`, `platform`,
  `architecture`, `fingerprint`.

For **TermsrvPatcherUnified only**, a checked and operator-reviewed
**Include Windows build, termsrv.dll version and SHA-256** option adds one
all-or-nothing typed evidence set: `windows_release`,
`windows_build`, `windows_ubr`, `dll_version` and `dll_sha256`.
The app calculates SHA-256 by reading the installed DLL locally, but
never uploads DLL bytes, file paths, the machine or account name,
raw stack traces, or the user's description. A SHA-256 of a custom DLL
may identify that exact custom binary: users may disable the option.

The same five optional fields are validated by the embedded collector,
the .NET HTTPS client and the Cloudflare Worker. Legacy v1 reports are
unchanged. The Worker creates a GitHub Issue with these typed metadata
only after explicit user confirmation and successful server setup.
GitHub Actions then validates the Issue again and records it in
`data/diagnostic-observations.csv` with `verification=unverified`.
These reports are claims, not proof of successful patching, and never
write or automatically authorize `Patterns/AutomaticPatterns.txt`.
Only actively reviewed, reproducible signatures can be promoted into
the verified pattern catalog.

**Important:** This does not mean anonymous delivery is deployed.
Until the operator deploys and enables the relay, reports can only be
stored locally or published through existing deliberate GitHub sign-in
methods. No direct GitHub token is stored in the EXE.

It does **not** copy free-text descriptions, credentials, hostnames, usernames,
local paths, IP addresses, stack traces, raw logs, or local delivery state into
the JSON. The receiver is assumed to publish the approved metadata in a
**PUBLIC GitHub Issue**; review before submission.

The client enforces HTTPS, a strict endpoint path, no redirects or cookies,
a matching fingerprint, and a bounded receipt containing the exact event ID,
project and an approved issue URL. The queue is marked `submitted` only after
a validated receipt; otherwise the report stays `pending`. In case of
uncertain delivery, check the server/Issue state before retrying.

## Administrator-only relay setup (not part of the EXE)

First deploy and secure the shared server reference, described in
[the relay README](https://github.com/sgennadi/UniversalDiagnocticsModule/blob/feature/universal-anonymous-relay-v1/relay/README.md).
This requires a server-only GitHub Issues credential, approved public repository
allowlist, rate limits, monitored retention and a kill switch.

Once deployed, a trusted administrator creates and ACL-protects:

`%PROGRAMDATA%\UniversalDiagnostics\relay.json`

with contents such as:

```json
{"endpoint":"https://YOUR-TRUSTED-RELAY.workers.dev/v1/diagnostics"}
```

The address is a placeholder, **not an operating endpoint**. Protect
`relay.json` from untrusted writes: HTTPS syntax checks cannot establish
that an arbitrary DNS host belongs to your organization. Endpoint
configuration alone is not proof of successful delivery.

"Anonymous" means the client needs no GitHub account or personal token.
It does **not** guarantee network-level anonymity: the receiver/network
operator can process source IP data for rate limits and abuse prevention.

The GitHub Actions synthetic suite uses mocked HTTP responses only; it never
creates actual issues or writes a system `termsrv.dll`.
