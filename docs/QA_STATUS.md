# Preview QA status - 2026-11-08

Version: 0.1.0-preview.3

## Completed in the Linux authoring container

- Retained and checked the original three automatic signatures and 16 user-provided manual entries.
- Reviewed .NET 10/WPF sources and introduced stricter HEX parsing.
- Added read-only near-match suggestions for unknown DLLs (no inferred replacement bytes).
- Added x64 PE DLL executable-section preflight before any protected-file write.
- Added CLI read-only report export, copy/save buttons, and UI busy-state protection.
- Added C# synthetic tests for the automatic patterns, manual groups, duplicate and partial matches, near-signature detection and PE boundaries.
- Extended Windows GitHub Actions to run the tests, publish the self-contained executable and inspect a fake DLL without modification.
- XML/XAML, catalog, resources and workflow source validation is performed by `scripts/verify_source.py`.

## Not completed / do not assume

- The .NET SDK is absent in this environment and outgoing access to install it failed, so **C# compilation and C# tests were not run here**.
- GitHub Actions has not run (no connected writable TermsrvPatcher Unified repository was found).
- No Windows VM was available to run the GUI or test protected DLL writes, service stop/restart or restore.
- Signature support for Windows 11 24H2/25H2/26H2 must be verified against actual DLL file versions; matching is not a certification of compatibility.
- Do not call this release stable or deploy it to managed client computers yet.

## Git-ready changes in preview.3

- Read-only CLI runs asInvoker; the interactive GUI attempts one UAC elevation.
- PE executable-region check moved into the preview stage (Apply also rechecks).
- `--reapply` has explicit non-zero exit statuses for unsupported/failed operations.
- GitHub setup script, security policy, issue template and contribution guidance added.
- No remote repository was created: GitHub connector lacks a create-repository action.
