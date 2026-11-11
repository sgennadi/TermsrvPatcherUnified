using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// One human-reviewed report with TWO separately classified public records.
/// The Google gateway and GitHub CSV aggregation remain schema-specific.
/// </summary>
internal sealed class UnifiedApplyReport
{
    internal AnonymousDiagnosticPayload Diagnostics { get; }
    internal string DiagnosticJson { get; }
    internal CompatibilityRelaySubmission Compatibility { get; }

    internal UnifiedApplyReport(SuccessfulFixMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        metadata.Validate();
        var environment = new DiagnosticEnvironment(
            metadata.WindowsRelease, metadata.WindowsBuild, metadata.Ubr,
            metadata.DllVersion, metadata.PatchedSha256);
        if (!environment.Valid)
            throw new InvalidDataException("Completed Apply diagnostics are incomplete.");

        Diagnostics = DiagnosticsBridge.PrepareDirect(
            new DiagnosticsBridge.DiagnosticDraft(
                "ProtectedApply", "VerifiedSuccess", "SUCCESS",
                "Completed protected Apply. No RDP connection test was made."),
            environment);
        DiagnosticJson = GoogleAppsScriptReportClient.BuildSubmission(Diagnostics);
        Compatibility = CompatibilityRelaySubmission.Create(metadata);
    }

    internal string ReviewedText =>
        "1. GENERAL DIAGNOSTICS - public GitHub Issue (unverified)\n" +
        DiagnosticJson +
        "\n\n2. DLL COMPATIBILITY - public GitHub Issue #1 comment (unverified)\n" +
        Compatibility.Json +
        "\n\nTwo separately validated public records are sent only with explicit approval.";
}
