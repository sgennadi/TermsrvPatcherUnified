using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Explicitly user-approved, anonymous-to-GitHub reporting through a pinned
/// Google Apps Script Web App deployment. No local queue, GitHub token,
/// credentials, cookies or automatic retry are involved.
/// </summary>
internal sealed class GoogleAppsScriptReportClient : IDisposable
{
    private static readonly Regex EndpointPath = new(
        @"^/macros/s/[A-Za-z0-9_-]{25,180}/exec$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private const string ExpectedProject = "sgennadi/TermsrvPatcherUnified";
    private const int MaxConfirmationBytes = 8192;
    private readonly HttpClient http;
    private readonly bool ownHttp;

    internal GoogleAppsScriptReportClient(HttpClient? injectedHttp = null)
    {
        http = injectedHttp ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(30) };
        ownHttp = injectedHttp is null;
    }

    internal static bool IsApprovedEndpoint(string? endpoint) =>
        endpoint is not null && endpoint.Length is >= 60 and <= 256 &&
        Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed) &&
        parsed.Scheme == Uri.UriSchemeHttps && parsed.IsDefaultPort &&
        parsed.UserInfo.Length == 0 && parsed.Query.Length == 0 &&
        parsed.Fragment.Length == 0 &&
        parsed.Host.Equals("script.google.com", StringComparison.OrdinalIgnoreCase) &&
        EndpointPath.IsMatch(parsed.AbsolutePath) &&
        string.Equals(endpoint, parsed.AbsoluteUri, StringComparison.Ordinal);

    internal static string BuildSubmission(AnonymousDiagnosticPayload payload)
    {
        var checkedPayload = UniversalDiagnosticsRelayClient.Prepare(payload.Json);
        if (payload.Project != ExpectedProject ||
            payload.EventId != checkedPayload.EventId ||
            payload.Project != checkedPayload.Project ||
            payload.Json != checkedPayload.Json)
            throw new InvalidDataException("Diagnostic fields changed after review.");
        using var document = JsonDocument.Parse(checkedPayload.Json);
        // The GitHub compatibility CSV only accepts complete Windows/DLL
        // observations. When unchecked the metadata must remain excluded;
        // use the local-only review option instead.
        if (!document.RootElement.GetProperty("event").TryGetProperty("dll_sha256", out _))
            throw new InvalidDataException(
                "GitHub archive requires Windows build and DLL evidence; no report was sent.");
        return checkedPayload.Json;
    }

    private static bool IsTrustedGoogleResultUri(Uri? uri) =>
        uri is not null && uri.Scheme == Uri.UriSchemeHttps &&
        uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.Host.Equals("script.googleusercontent.com", StringComparison.OrdinalIgnoreCase) &&
        uri.AbsolutePath.Equals("/macros/echo", StringComparison.Ordinal) &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 4096;

    internal Task<Uri> SendAsync(string endpoint, string reviewedJson,
        AnonymousDiagnosticPayload payload, CancellationToken cancellationToken = default)
    {
        if (reviewedJson != BuildSubmission(payload))
            throw new InvalidDataException("Report changed after confirmation.");
        return SendApprovedJsonAsync(endpoint, reviewedJson, requireCommentReceipt: false,
            cancellationToken);
    }

    internal Task<Uri> SendCompatibilityAsync(string endpoint, string reviewedJson,
        CompatibilityRelaySubmission submission,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(submission);
        submission.Validate();
        if (!string.Equals(reviewedJson, submission.Json, StringComparison.Ordinal))
            throw new InvalidDataException("Compatibility metadata changed after confirmation.");
        return SendApprovedJsonAsync(endpoint, reviewedJson, requireCommentReceipt: true,
            cancellationToken);
    }

    private async Task<Uri> SendApprovedJsonAsync(string endpoint, string reviewedJson,
        bool requireCommentReceipt, CancellationToken cancellationToken)
    {
        if (!IsApprovedEndpoint(endpoint))
            throw new ArgumentException("Unrecognized Google Apps Script deployment address.");
        using var post = new HttpRequestMessage(HttpMethod.Post, endpoint);
        post.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        post.Headers.UserAgent.Add(new ProductInfoHeaderValue("TermsrvPatcherUnified", "0.1"));
        post.Content = new StringContent(reviewedJson, Encoding.UTF8, "application/json");

        using var first = await http.SendAsync(post, HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (first.RequestMessage?.RequestUri?.AbsoluteUri != endpoint)
            throw new InvalidDataException("Unexpected submission destination; delivery is uncertain.");

        // ContentService returns a one-time redirect to Google's own result
        // host. A GET only retrieves the receipt; no diagnostic bytes or
        // authorization headers are ever forwarded to that second host.
        if (first.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther)
        {
            Uri? location = first.Headers.Location;
            if (!IsTrustedGoogleResultUri(location))
                throw new InvalidDataException("Google confirmation redirected outside the approved host.");
            using var get = new HttpRequestMessage(HttpMethod.Get, location);
            get.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var receipt = await http.SendAsync(get,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (receipt.RequestMessage?.RequestUri?.AbsoluteUri != location!.AbsoluteUri)
                throw new InvalidDataException("Google confirmation changed destination.");
            return await ParseReceiptAsync(receipt, cancellationToken, requireCommentReceipt);
        }
        return await ParseReceiptAsync(first, cancellationToken, requireCommentReceipt);
    }

    internal static async Task<Uri> ParseReceiptAsync(HttpResponseMessage response,
        CancellationToken cancellationToken = default, bool requireCommentReceipt = false)
    {
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException(
                "Reporting service did not confirm delivery (HTTP " +
                (int)response.StatusCode + "). Check GitHub Issues before retrying.");
        if (response.Content.Headers.ContentLength is > MaxConfirmationBytes)
            throw new InvalidDataException("Reporting confirmation exceeds the size limit.");
        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        byte[] part = new byte[2048];
        int n;
        while ((n = await responseStream.ReadAsync(part, cancellationToken)) > 0)
        {
            if (buffer.Length + n > MaxConfirmationBytes)
                throw new InvalidDataException("Reporting confirmation exceeds the size limit.");
            buffer.Write(part, 0, n);
        }
        buffer.Position = 0;
        using var document = JsonDocument.Parse(buffer);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Reporting confirmation has an invalid format.");

        var root = document.RootElement;
        if (!root.TryGetProperty("ok", out var status) ||
            status.ValueKind != JsonValueKind.True)
        {
            var error = root.TryGetProperty("error", out var reason) &&
                        reason.ValueKind == JsonValueKind.String ? reason.GetString() : "";
            var userMessage = error switch
            {
                "daily_limit" => "The public report limit for today was reached.",
                "busy" => "The reporting service is busy.",
                "invalid_evidence" => requireCommentReceipt
                    ? "The Google receiver rejected the DLL compatibility payload. " +
                      "Its published Apps Script deployment may be outdated: " +
                      "Deploy > Manage deployments > Edit > New version. " +
                      "If already updated, inspect the compatibility schema and permissions."
                    : "The service rejected incomplete or invalid Windows details.",
                "not_configured" => "The Google reporting bridge needs an owner-side GitHub token.",
                "github_not_confirmed" => requireCommentReceipt
                    ? "GitHub did not confirm the Issue #1 compatibility comment. " +
                      "Verify that the Google-side GitHub token can write issue comments."
                    : "GitHub did not confirm issue creation.",
                "github_receipt_invalid" => "GitHub returned an unexpected issue receipt.",
                "temporarily_unavailable" => "The reporting service is temporarily unavailable.",
                _ => "The reporting service could not confirm receipt."
            };
            throw new InvalidOperationException(
                userMessage + " Check GitHub Issues before sending again.");
        }

        if (!root.TryGetProperty("issue_url", out var issue) ||
            issue.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(issue.GetString(), UriKind.Absolute, out var issueUri) ||
            !GitHubIssuePublisher.IsApprovedIssueUri(issueUri))
            throw new InvalidDataException(
                "Reporting service returned an invalid GitHub issue address. Check Issues before retrying.");
        if (requireCommentReceipt)
        {
            if (!root.TryGetProperty("comment_url", out var comment) ||
                comment.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(comment.GetString(), UriKind.Absolute, out var commentUri) ||
                !Regex.IsMatch(commentUri.AbsoluteUri,
                    @"\Ahttps://github\.com/sgennadi/TermsrvPatcherUnified/issues/1#issuecomment-[1-9][0-9]*\z",
                    RegexOptions.CultureInvariant) ||
                issueUri.AbsoluteUri !=
                    "https://github.com/sgennadi/TermsrvPatcherUnified/issues/1")
                throw new InvalidDataException(
                    "Google did not confirm a compatibility comment in the approved repository.");
            return commentUri;
        }
        return issueUri;
    }

    public void Dispose()
    {
        if (ownHttp) http.Dispose();
    }
}
