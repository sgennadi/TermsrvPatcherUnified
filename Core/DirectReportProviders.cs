using UniversalDiagnostics.Transport;
using System.Text.Json;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Optional, public *identifiers* for two receiver-free transports.
/// No access tokens, credentials, user identities, paths or passwords are saved.
/// Values may also be provided directly in the Diagnostics UI for one session.
/// </summary>
internal sealed record DirectReportingSettings(string FormspreeFormId, string GitHubOAuthClientId)
{
    internal static bool ValidFormId(string? id) => ReportingProviderIdentifiers.ValidFormId(id);
    internal static bool ValidClientId(string? id) => ReportingProviderIdentifiers.ValidClientId(id);

    internal static DirectReportingSettings Load()
    {
        string path = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData),
            "TermsrvPatcherUnified", "reporting.json");
        if (!File.Exists(path)) return new("", "");
        if (new FileInfo(path).Length > 4096)
            throw new InvalidDataException("Reporting configuration exceeds its limit.");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            root.EnumerateObject().Any(x => x.Name is not ("formspree_form_id" or "github_oauth_client_id")))
            throw new InvalidDataException("Unknown reporting configuration field.");
        string Read(string name)
        {
            if (!root.TryGetProperty(name, out var item)) return "";
            return item.ValueKind == JsonValueKind.String
                ? item.GetString() ?? "" : throw new InvalidDataException("Invalid reporting configuration.");
        }
        var settings = new DirectReportingSettings(Read("formspree_form_id"),
            Read("github_oauth_client_id"));
        if ((settings.FormspreeFormId.Length > 0 && !ValidFormId(settings.FormspreeFormId)) ||
            (settings.GitHubOAuthClientId.Length > 0 && !ValidClientId(settings.GitHubOAuthClientId)))
            throw new InvalidDataException("Invalid provider identifier in reporting configuration.");
        return settings;
    }
}

