using System.Reflection;
using System.Text.Json;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Public provider identifiers are embedded at BUILD TIME in the single EXE.
/// No per-computer ProgramData file, environment lookup, mutable user overrides,
/// tokens, passwords, or HTTP initialization is necessary.
/// </summary>
internal sealed record DirectReportingSettings(string FormspreeFormId, string GitHubOAuthClientId)
{
    internal const string ResourceName = "TermsrvPatcherUnified.ReportingProviders";

    internal bool HasFormspree => ValidFormId(FormspreeFormId);
    internal bool HasGitHubOAuth => ValidClientId(GitHubOAuthClientId);
    internal bool HasBoth => HasFormspree && HasGitHubOAuth;

    internal static bool ValidFormId(string? id) => ReportingProviderIdentifiers.ValidFormId(id);
    internal static bool ValidClientId(string? id) => ReportingProviderIdentifiers.ValidClientId(id);

    internal static DirectReportingSettings Load()
    {
        using var stream = typeof(DirectReportingSettings).Assembly
            .GetManifestResourceStream(ResourceName);
        // CI builds can intentionally be unconfigured. UI must fail closed:
        // disabled send controls, never fake working Formspree/GitHub IDs.
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
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in root.EnumerateObject())
        {
            if (!names.Add(field.Name) ||
                field.Name is not ("formspree_form_id" or "github_oauth_client_id") ||
                field.Value.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Unknown, repeated or invalid provider field.");
        }
        var form = root.TryGetProperty("formspree_form_id", out var f)
            ? f.GetString() ?? "" : "";
        var github = root.TryGetProperty("github_oauth_client_id", out var g)
            ? g.GetString() ?? "" : "";
        if ((form.Length != 0 && !ValidFormId(form)) ||
            (github.Length != 0 && !ValidClientId(github)))
            throw new InvalidDataException("Invalid embedded provider identifier.");
        return new(form, github);
    }
}
