using System.Text.Json;
using System.Text.Json.Nodes;
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

    /// <summary>Records a confirmed issue URL locally; never performs a network request.</summary>
    public static void MarkSubmitted(string path, string eventId, Uri issueUrl)
    {
        if (!Guid.TryParseExact(eventId, "D", out _) ||
            !GitHubIssuePublisher.IsApprovedIssueUri(issueUrl))
            throw new InvalidDataException("The report ID or GitHub Issue URL is invalid.");
        var expected = Path.GetFullPath(Path.Combine(
            UniversalDiagnosticsEmbedded.QueueDirectory(Project), eventId + ".json"));
        if (!string.Equals(Path.GetFullPath(path), expected, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The report must be in this project's local queue.");
        lock (Gate)
        {
            var node = JsonNode.Parse(File.ReadAllText(expected)) as JsonObject ??
                throw new InvalidDataException("Invalid local diagnostic report.");
            if (node["event"]?["id"]?.GetValue<string>() != eventId ||
                node["event"]?["project"]?.GetValue<string>() != Project)
                throw new InvalidDataException("Diagnostic report identity mismatch.");
            if (node["delivery"]?["status"]?.GetValue<string>() == "submitted")
                throw new InvalidOperationException("This report is already marked as submitted.");
            node["delivery"] = new JsonObject
            {
                ["status"] = "submitted",
                ["url"] = issueUrl.AbsoluteUri,
                ["at_utc"] = DateTimeOffset.UtcNow.ToString("O")
            };
            var staging = Path.Combine(Path.GetDirectoryName(expected)!,
                ".udx-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var output = new FileStream(staging, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None))
                {
                    var bytes = JsonSerializer.SerializeToUtf8Bytes(node,
                        new JsonSerializerOptions { WriteIndented = true });
                    if (bytes.Length > 65_536)
                        throw new InvalidDataException("Local diagnostic record is too large.");
                    output.Write(bytes);
                    output.Flush(true);
                }
                File.Move(staging, expected, overwrite: true);
            }
            finally { if (File.Exists(staging)) File.Delete(staging); }
        }
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

