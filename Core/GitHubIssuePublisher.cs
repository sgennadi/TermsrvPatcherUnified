using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// An explicitly invoked, pinned-repository publisher. No background delivery,
/// persistent credentials, redirects, or raw diagnostic files are uploaded.
/// An injected HTTP client permits completely offline Windows CI tests.
/// </summary>
internal sealed class GitHubIssuePublisher : IDisposable
{
    private const string Endpoint = "https://api.github.com/repos/sgennadi/TermsrvPatcherUnified/issues";
    private const int MaxReportChars = 8_000;
    private const int MaxResponseBytes = 128 * 1024;
    private static readonly Regex IssuePath = new(
        @"^/sgennadi/TermsrvPatcherUnified/issues/[1-9][0-9]*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly HttpClient client;
    private readonly bool ownsClient;

    public GitHubIssuePublisher(HttpClient? injectedClient = null)
    {
        client = injectedClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(25) };
        ownsClient = injectedClient is null;
    }

    internal static bool IsApprovedIssueUri(Uri? uri) => uri is not null &&
        uri.Scheme == Uri.UriSchemeHttps &&
        uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        IssuePath.IsMatch(Uri.UnescapeDataString(uri.AbsolutePath));

    public async Task<Uri> PublishAsync(string reviewedReport, string eventId, string sessionToken,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParseExact(eventId, "D", out _) ||
            string.IsNullOrWhiteSpace(reviewedReport) ||
            reviewedReport.Length > MaxReportChars ||
            !reviewedReport.Contains($"<!-- udx-report-id:{eventId} -->", StringComparison.Ordinal) ||
            !reviewedReport.Contains("- Project: `sgennadi/TermsrvPatcherUnified`", StringComparison.Ordinal) ||
            !reviewedReport.Contains("## Universal Diagnostics (operator-reviewed)", StringComparison.Ordinal))
            throw new ArgumentException("Publish requires a saved, reviewed report for this project.");

        // GitHub fine-grained and classic PATs are accepted. Never store, log or
        // place a token in a URL; reject control characters and whitespace.
        if (string.IsNullOrEmpty(sessionToken) || sessionToken.Length is < 20 or > 512 ||
            sessionToken.Any(c => c < '!' || c > '~'))
            throw new ArgumentException("Enter a valid temporary GitHub Issues write token.");

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", sessionToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("TermsrvPatcherUnified", "0.1"));
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        var payload = JsonSerializer.Serialize(new
        {
            title = "[Diagnostics] TermsrvPatcherUnified report " + eventId[..8],
            body = reviewedReport
        });
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await client.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // Defense-in-depth: a custom/injected HttpClient must not follow a
        // redirect with the bearer credential to an unexpected destination.
        if (response.RequestMessage?.RequestUri is not { } finalUri ||
            !string.Equals(finalUri.AbsoluteUri, Endpoint, StringComparison.Ordinal))
            throw new InvalidDataException("GitHub endpoint changed unexpectedly; status is unknown.");
        if (response.StatusCode != HttpStatusCode.Created)
            throw new InvalidOperationException($"Issue submission was not confirmed (HTTP {(int)response.StatusCode}). " +
                "Check Issues:write permission and the repository settings; verify GitHub before retrying.");
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            throw new InvalidDataException("GitHub confirmation was too large; verify the issue before retrying.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var limited = new MemoryStream();
        var buffer = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (limited.Length + read > MaxResponseBytes)
                throw new InvalidDataException("GitHub confirmation was too large; verify before retrying.");
            limited.Write(buffer, 0, read);
        }
        limited.Position = 0;
        using var document = JsonDocument.Parse(limited);
        if (!document.RootElement.TryGetProperty("html_url", out var property) ||
            property.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(property.GetString(), UriKind.Absolute, out var issueUrl) ||
            !IsApprovedIssueUri(issueUrl))
            throw new InvalidDataException("GitHub returned an unexpected issue URL; verify the issue before retrying.");
        return issueUrl;
    }

    public void Dispose()
    {
        if (ownsClient) client.Dispose();
    }
}
