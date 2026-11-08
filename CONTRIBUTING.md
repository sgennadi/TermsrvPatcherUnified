# Contributing

Contributions and bug fixes are welcome under GPLv3. Preserve the original attribution in `NOTICE.md` and the MIT notice for adapted automatic patterns.

## Before a pull request

1. Run `python scripts/verify_source.py`.
2. On Windows with .NET 10 SDK: `dotnet run --project Tests/TermsrvPatcher.Tests.csproj -c Release`.
3. Do not introduce new automatic patterns without a reproducible tested file-version and code-region review. A single matching byte sequence is not a guarantee that a patch is safe.
4. Do not add scripts or tasks that silently elevate or repeatedly modify files without administrator consent.
5. Include tests for parser/PE safety failures and rollback behavior when modifying protected-file logic.

Do not commit any system DLLs, per-machine logs, credentials, GitHub tokens, or backup files.
