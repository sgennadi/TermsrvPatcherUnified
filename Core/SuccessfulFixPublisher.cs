using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>One small verified byte-range change; never a whole system DLL.</summary>
internal sealed record ChangedBytes(long Offset, string Before, string After);

/// <summary>
/// Opt-in compatibility report from a successful, verified Apply operation.
/// Contains version, original/result SHA-256 and exact changed ranges only.
/// No host, user, network identifiers, paths, full DLL or diagnostic logs.
/// </summary>
internal sealed record SuccessfulFixMetadata(
    string WindowsName, string WindowsRelease, int WindowsBuild, int Ubr,
    string DllVersion, string ApplicationVersion, string Mode,
    string OriginalSha256, string PatchedSha256, IReadOnlyList<ChangedBytes> Changes)
{
    private static readonly Regex Version = new(
        @"\A[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Release = new(
        @"\A[0-9A-Za-z._-]{1,20}\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex AppVersion = new(
        @"\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Hash = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Bytes = new(
        @"\A(?:[0-9A-F]{2}){1,64}\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// FileVersionInfo.FileVersion often contains an additional OS resource
    /// description such as "10.0.26100.8115 (WinBuild.160101.0800)".
    /// Keep that raw value for protected backup/journal identity, but publish
    /// only the strict, numeric version required by the Google schema.
    /// Reject unknown suffixes rather than silently stripping arbitrary text.
    /// </summary>
    internal static string? CanonicalDllVersion(string? version)
    {
        if (string.IsNullOrEmpty(version)) return null;
        var match = Regex.Match(version,
            @"\A(?<numeric>[0-9]{1,5}(?:\.[0-9]{1,8}){1,4})(?: \(WinBuild\.[0-9]+(?:\.[0-9]+){1,3}\))?\z",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["numeric"].Value : null;
    }

    internal static SuccessfulFixMetadata FromSuccessfulApply(WindowsDetails details, PatchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(details);
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.State != PatchState.Ready || plan.PatchedBytes is null ||
            plan.Edits.Count == 0)
            throw new InvalidOperationException("Only a verified successful Apply can be reported.");
        var record = new SuccessfulFixMetadata(
            details.Name, details.DisplayVersion, details.Build, details.Ubr,
            CanonicalDllVersion(plan.FileVersion) ??
                throw new InvalidDataException("DLL version contains unsupported resource metadata."),
            UpdateIntegration.Version, plan.IsManual ? "manual" : "automatic",
            plan.OriginalSha256.ToLowerInvariant(), SystemInfo.Sha256(plan.PatchedBytes),
            plan.Edits.Select(edit => new ChangedBytes(edit.Offset,
                Convert.ToHexString(edit.Expected), Convert.ToHexString(edit.Replacement)))
                .OrderBy(edit => edit.Offset).ToArray());
        record.Validate();
        return record;
    }

    internal void Validate()
    {
        if (WindowsName is not ("Windows 10" or "Windows 11") ||
            WindowsBuild is < 19041 or > 99999 || Ubr is < 0 or > 999999 ||
            !Release.IsMatch(WindowsRelease) || !Version.IsMatch(DllVersion) ||
            !AppVersion.IsMatch(ApplicationVersion) || Mode is not ("manual" or "automatic") ||
            string.IsNullOrWhiteSpace(OriginalSha256) || !Hash.IsMatch(OriginalSha256) ||
            string.IsNullOrWhiteSpace(PatchedSha256) || !Hash.IsMatch(PatchedSha256) ||
            OriginalSha256 == PatchedSha256 || Changes is not { Count: > 0 and <= 16 })
            throw new InvalidDataException("Compatibility report contains invalid metadata.");
        long lastEnd = 0;
        foreach (var change in Changes.OrderBy(c => c.Offset))
        {
            if (change.Offset < lastEnd || change.Offset > uint.MaxValue ||
                string.IsNullOrWhiteSpace(change.Before) ||
                string.IsNullOrWhiteSpace(change.After) ||
                !Bytes.IsMatch(change.Before) || !Bytes.IsMatch(change.After) ||
                change.Before.Length != change.After.Length ||
                change.Before == change.After)
                throw new InvalidDataException("Compatibility report contains unsafe byte changes.");
            lastEnd = checked(change.Offset + change.Before.Length / 2);
        }
    }

    internal string AsComment()
    {
        Validate();
        var entries = string.Join("|", Changes.OrderBy(e => e.Offset)
            .Select(e => $"0x{e.Offset:X8}:{e.Before}>{e.After}"));
        return "termsrv-success/v2\n" +
               $"windows={WindowsName}\n" +
               $"release={WindowsRelease}\n" +
               $"build={WindowsBuild}\n" +
               $"ubr={Ubr}\n" +
               "file=termsrv.dll\n" +
               $"dll={DllVersion}\n" +
               $"app={ApplicationVersion}\n" +
               $"mode={Mode}\n" +
               $"original_sha256={OriginalSha256}\n" +
               $"patched_sha256={PatchedSha256}\n" +
               $"edits={entries}";
    }
}

internal sealed class SuccessfulFixPublisher : IDisposable
{
    private const string Endpoint =
        "https://api.github.com/repos/sgennadi/TermsrvPatcherUnified/issues/1/comments";
    private readonly HttpClient http;
    private readonly bool ownsHttp;

    internal SuccessfulFixPublisher(HttpClient? injectedClient = null)
    {
        http = injectedClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(25) };
        ownsHttp = injectedClient is null;
    }

    internal Task PublishAsync(SuccessfulFixMetadata metadata, string sessionToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        return PublishBodyAsync(metadata.AsComment(), sessionToken, cancellationToken);
    }

    internal Task PublishAsync(OfflineFixMetadata metadata, string sessionToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        return PublishBodyAsync(metadata.AsComment(), sessionToken, cancellationToken);
    }

    private async Task PublishBodyAsync(string report, string sessionToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sessionToken) || sessionToken.Length is < 20 or > 512 ||
            sessionToken.Any(c => c < '!' || c > '~'))
            throw new ArgumentException("Provide a GitHub Issues write token for this session.");

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sessionToken);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("TermsrvPatcherUnified", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        request.Content = new StringContent(JsonSerializer.Serialize(new { body = report }),
            Encoding.UTF8, "application/json");

        using var response = await http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.RequestMessage?.RequestUri?.AbsoluteUri != Endpoint)
            throw new InvalidDataException("Unexpected GitHub compatibility endpoint.");
        if (response.StatusCode != HttpStatusCode.Created)
            throw new InvalidOperationException($"GitHub did not confirm the compatibility report (HTTP {(int)response.StatusCode}).");
        // Only the status code is used. Never copy the response body or credentials
        // into the audit log or diagnostic event.
    }

    public void Dispose()
    {
        if (ownsHttp) http.Dispose();
    }
}
