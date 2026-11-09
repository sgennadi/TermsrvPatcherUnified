using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Compatibility metadata from a COMPLETED operation, not a remote diagnostic.
/// No host/user/network identifiers, paths, binary hashes or logs are included.
/// </summary>
internal sealed record SuccessfulFixMetadata(
    string WindowsName, string WindowsRelease, int WindowsBuild, int Ubr,
    string DllVersion, string ApplicationVersion, string Mode)
{
    private static readonly Regex Version = new(
        @"^[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Release = new(
        @"^[0-9A-Za-z._-]{1,20}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex AppVersion = new(
        @"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    internal static SuccessfulFixMetadata FromSuccessfulApply(WindowsDetails details, PatchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(details);
        ArgumentNullException.ThrowIfNull(plan);
        var record = new SuccessfulFixMetadata(details.Name, details.DisplayVersion,
            details.Build, details.Ubr, plan.FileVersion, UpdateIntegration.Version,
            plan.IsManual ? "manual" : "automatic");
        record.Validate();
        return record;
    }

    internal void Validate()
    {
        if (WindowsName is not ("Windows 10" or "Windows 11") ||
            WindowsBuild is < 19041 or > 99999 || Ubr is < 0 or > 999999 ||
            !Release.IsMatch(WindowsRelease) || !Version.IsMatch(DllVersion) ||
            !AppVersion.IsMatch(ApplicationVersion) || Mode is not ("manual" or "automatic"))
            throw new InvalidDataException("Compatibility report contains invalid version metadata.");
    }

    internal string AsComment()
    {
        Validate();
        return "termsrv-success/v1\n" +
               $"windows={WindowsName}\n" +
               $"release={WindowsRelease}\n" +
               $"build={WindowsBuild}\n" +
               $"ubr={Ubr}\n" +
               "file=termsrv.dll\n" +
               $"dll={DllVersion}\n" +
               $"app={ApplicationVersion}\n" +
               $"mode={Mode}";
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

    internal async Task PublishAsync(SuccessfulFixMetadata metadata, string sessionToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        var report = metadata.AsComment();
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
