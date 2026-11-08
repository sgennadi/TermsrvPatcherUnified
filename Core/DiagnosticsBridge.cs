using System.Text.Json;
using UniversalDiagnostics;

namespace TermsrvPatcherUnified.Core;

// Uses the unchanged in-process UniversalDiagnosticsEmbedded canonical .NET collector.
// Errors are remembered in memory; recording requires explicit operator review.
internal static class DiagnosticsBridge
{
    public const string Project = "sgennadi/TermsrvPatcherUnified";
    private static readonly object Gate = new();
    private static DiagnosticDraft? last;

    internal sealed record DiagnosticDraft(string Component, string ErrorType, string Code, string Summary);

    public static void Remember(string component, Exception exception)
    {
        var name = exception.GetType().Name;
        var draft = new DiagnosticDraft(component, name,
            $"0x{exception.HResult:X8}", $"{name} occurred in {component}. Describe what you were doing.");
        lock (Gate) last = draft;
    }

    public static DiagnosticDraft Current()
    {
        lock (Gate)
            return last ?? new DiagnosticDraft("Application", "USER_REPORT", "MANUAL",
                "Describe the issue without personal information or credentials.");
    }

    public static UniversalDiagnosticsEmbedded.Receipt Capture(DiagnosticDraft draft, string summary)
    {
        // Do not include raw exception messages, logs, IPs, machine/user names or paths.
        var safeRequest = JsonSerializer.Serialize(new
        {
            project = Project,
            component = draft.Component,
            error_type = draft.ErrorType,
            code = draft.Code,
            version = UpdateIntegration.Version,
            summary,
            level = "error"
        });
        return UniversalDiagnosticsEmbedded.Capture(safeRequest);
    }

    public static string ReportMarkdown(string json)
    {
        using var document = JsonDocument.Parse(json);
        var ev = document.RootElement.GetProperty("event");
        string Get(string property) => ev.GetProperty(property).GetString() ?? "";
        static string Text(string value) => value.Replace('`', '\'').Replace('|', '/');
        return $"<!-- udx-report-id:{Get("id")} -->\n" +
            "## Universal Diagnostics (operator-reviewed)\n\n" +
            $"- Schema: `universal-diagnostics/v1`\n" +
            $"- Project: `{Project}`\n" +
            $"- Component: {Text(Get("component"))}\n" +
            $"- App version: {Text(Get("version"))}\n" +
            $"- Severity: {Text(Get("level"))}\n" +
            $"- Error class: {Text(Get("error_type"))}\n" +
            $"- Error code: {Text(Get("code"))}\n" +
            $"- Observed UTC: {Text(Get("timestamp_utc"))}\n" +
            $"- OS: {Text(Get("platform"))}\n" +
            $"- Architecture: {Text(Get("architecture"))}\n" +
            $"- Fingerprint: `{Get("fingerprint")}`\n\n" +
            "### Description (redacted)\n" + Text(Get("summary")) +
            "\n\nReview every line before publishing. No raw logs are attached.";
    }
}
