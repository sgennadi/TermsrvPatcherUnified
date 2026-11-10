using System.Text.Json;
using System.Text.Json.Nodes;
using UniversalDiagnostics;
using UniversalDiagnostics.Transport;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

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

    public static UniversalDiagnosticsEmbedded.Receipt Capture(
        DiagnosticDraft draft, string summary, DiagnosticEnvironment? environment = null)
    {
        // This optional diagnostic is chosen after a separate preview. No
        // paths, accounts, IP addresses, DLL bytes or raw exception messages
        // are inserted into the canonical local/anonymous report.
        if (environment is not null && !environment.Valid)
            throw new InvalidDataException("Diagnostic Windows/DLL metadata is invalid.");
        var fields = new Dictionary<string, object>
        {
            ["project"] = Project,
            ["component"] = draft.Component,
            ["error_type"] = draft.ErrorType,
            ["code"] = draft.Code,
            ["version"] = UpdateIntegration.Version,
            ["summary"] = summary,
            ["level"] = "error"
        };
        if (environment is not null)
        {
            fields["windows_release"] = environment.WindowsRelease;
            fields["windows_build"] = environment.WindowsBuild;
            fields["windows_ubr"] = environment.WindowsUbr;
            fields["dll_version"] = environment.DllVersion;
            fields["dll_sha256"] = environment.DllSha256;
        }
        return UniversalDiagnosticsEmbedded.Capture(JsonSerializer.Serialize(fields));
    }

    /// <summary>
    /// Prepare the same strict typed v1 metadata in memory for Formspree.
    /// Unlike Capture(), this method never writes a local queue record.
    /// Descriptions, raw errors, usernames, paths, passwords and DLL bytes
    /// are not included in the outbound payload.
    /// </summary>
    internal static AnonymousDiagnosticPayload PrepareDirect(
        DiagnosticDraft draft, DiagnosticEnvironment? environment = null)
    {
        if (environment is not null && !environment.Valid)
            throw new InvalidDataException("Unverified Windows/DLL evidence.");
        string architecture = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "AMD64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "ARM64",
            _ => "Other"
        };
        string[] identity = { Project, draft.Component, draft.ErrorType, draft.Code };
        string digestInput = string.Join("|", identity.Select(x => x.ToLowerInvariant()));
        string fingerprint = Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(digestInput)));
        var fields = new Dictionary<string, object>
        {
            ["schema"] = "universal-diagnostics/v1",
            ["id"] = Guid.NewGuid().ToString("D"),
            ["timestamp_utc"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["project"] = Project,
            ["component"] = draft.Component,
            ["error_type"] = draft.ErrorType,
            ["code"] = draft.Code,
            ["level"] = draft.ErrorType == "VerifiedSuccess" ? "info" : "error",
            ["version"] = UpdateIntegration.Version,
            ["platform"] = "Windows",
            ["architecture"] = architecture,
            ["fingerprint"] = fingerprint
        };
        if (environment is not null)
        {
            fields["windows_release"] = environment.WindowsRelease;
            fields["windows_build"] = environment.WindowsBuild;
            fields["windows_ubr"] = environment.WindowsUbr;
            fields["dll_version"] = environment.DllVersion;
            fields["dll_sha256"] = environment.DllSha256;
        }
        return UniversalDiagnosticsRelayClient.Prepare(
            JsonSerializer.Serialize(new { @event = fields }));
    }

    /// <summary>Records a confirmed GitHub Issue URL locally; no network request.</summary>
    public static void MarkSubmitted(string path, string eventId, Uri issueUrl)
    {
        if (!Guid.TryParseExact(eventId, "D", out _) ||
            !GitHubIssuePublisher.IsApprovedIssueUri(issueUrl))
            throw new InvalidDataException("The report ID or GitHub Issue URL is invalid.");
        RecordDelivery(path, eventId, "github", issueUrl.AbsoluteUri, null);
    }

    private static void RecordDelivery(string path, string eventId, string provider,
        string? confirmedUrl, string? formId)
    {
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
                ["provider"] = provider,
                ["url"] = confirmedUrl,
                ["form_id"] = formId,
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
        string EnvironmentLine()
        {
            if (!ev.TryGetProperty("windows_release", out var release) ||
                !ev.TryGetProperty("windows_build", out var build) ||
                !ev.TryGetProperty("windows_ubr", out var ubr) ||
                !ev.TryGetProperty("dll_version", out var dll) ||
                !ev.TryGetProperty("dll_sha256", out var hash))
                return "";
            return $"- Windows release: {Text(release.GetString() ?? "")}\n" +
                $"- Windows build: {build.GetInt32()}\n" +
                $"- Windows UBR: {ubr.GetInt32()}\n" +
                $"- DLL version: {Text(dll.GetString() ?? "")}\n" +
                $"- DLL SHA-256: `{hash.GetString()}`\n";
        }
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
            $"- Fingerprint: `{Get("fingerprint")}`\n" +
            EnvironmentLine() + "\n" +
            "### Description (redacted)\n" + Text(Get("summary")) +
            "\n\nReview every line before publishing. No raw logs are attached.";
    }
}

