using System.Text.Json;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Public Google endpoint and optional OAuth client ID are embedded in the EXE.
/// No credentials or tokens. Silent reporting requires separate protected
/// machine-wide consent after a fully acknowledged, operator-reviewed Apply report.
/// </summary>
internal sealed record DirectReportingSettings(string GoogleAppsScriptUrl, string GitHubOAuthClientId)
{
    internal const string ResourceName = "TermsrvPatcherUnified.ReportingProviders";
    internal bool HasGoogleScript => GoogleAppsScriptReportClient.IsApprovedEndpoint(GoogleAppsScriptUrl);
    internal bool HasGitHubOAuth => ReportingProviderIdentifiers.ValidClientId(GitHubOAuthClientId);
    internal bool HasBoth => HasGoogleScript && HasGitHubOAuth;
    internal static bool ValidClientId(string? id) => ReportingProviderIdentifiers.ValidClientId(id);

    internal static DirectReportingSettings Load()
    {
        using var stream = typeof(DirectReportingSettings).Assembly.GetManifestResourceStream(ResourceName);
        if (stream is null) return new("", "");
        if (stream.Length is < 2 or > 4096)
            throw new InvalidDataException("Embedded reporting configuration is invalid.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    internal static DirectReportingSettings Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 4096)
            throw new InvalidDataException("Invalid embedded reporting configuration length.");
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Embedded reporting configuration must be an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in root.EnumerateObject())
        {
            if (!seen.Add(field.Name) ||
                field.Name is not ("google_apps_script_url" or "github_oauth_client_id") ||
                field.Value.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Unknown, duplicate or invalid reporting field.");
        }
        string endpoint = root.TryGetProperty("google_apps_script_url", out var url)
            ? url.GetString() ?? "" : "";
        string oauth = root.TryGetProperty("github_oauth_client_id", out var client)
            ? client.GetString() ?? "" : "";
        if ((endpoint.Length > 0 && !GoogleAppsScriptReportClient.IsApprovedEndpoint(endpoint)) ||
            (oauth.Length > 0 && !ValidClientId(oauth)))
            throw new InvalidDataException("Invalid embedded Google endpoint or GitHub OAuth client ID.");
        return new(endpoint, oauth);
    }
}
