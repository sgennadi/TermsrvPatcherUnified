// Portable UniversalDiagnostics .NET 8+ optional GitHub device-flow transport.
// Link as source alongside UniversalDiagnosticsRelayClient.cs.
// Provider OAuth tokens MUST remain in process memory and never enter diagnostics.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UniversalDiagnostics.Transport;

internal static class ReportingProviderIdentifiers
{
    private static readonly Regex ClientId = new(
        @"\A[A-Za-z0-9._-]{8,100}\z", RegexOptions.CultureInvariant);
    internal static bool ValidClientId(string? id) => ClientId.IsMatch(id ?? "");
}

/// <summary>
/// Optional GitHub OAuth App device-flow authorization.
/// </summary>
internal sealed record GitHubDeviceChallenge(
    string ClientId, string DeviceCode, string UserCode, Uri VerificationUri,
    int ExpiresInSeconds, int PollIntervalSeconds);

internal sealed class GitHubDeviceAuthorization : IDisposable
{
    private const string DeviceUrl = "https://github.com/login/device/code";
    private const string TokenUrl = "https://github.com/login/oauth/access_token";
    private static readonly Regex Code = new(@"\A[A-Za-z0-9_-]{8,256}\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex UserCode = new(@"\A[A-Z0-9]{4}-[A-Z0-9]{4}\z",
        RegexOptions.CultureInvariant);

    private readonly HttpClient client;
    private readonly bool ownsClient;

    internal GitHubDeviceAuthorization(HttpClient? injected = null)
    {
        client = injected ?? new HttpClient(new HttpClientHandler {
            AllowAutoRedirect = false, UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(25) };
        ownsClient = injected is null;
    }

    internal async Task<GitHubDeviceChallenge> RequestCodeAsync(string clientId,
        CancellationToken cancellationToken = default)
    {
        if (!ReportingProviderIdentifiers.ValidClientId(clientId))
            throw new ArgumentException("Configure a valid GitHub OAuth App client ID.");
        using var form = new FormUrlEncodedContent(new Dictionary<string,string> {
            ["client_id"] = clientId,
            ["scope"] = "public_repo"
        });
        using var json = await SendJsonAsync(DeviceUrl, form, cancellationToken);
        var root = json.RootElement;
        string device = GetString(root, "device_code");
        string code = GetString(root, "user_code");
        string url = GetString(root, "verification_uri");
        int expires = GetInt(root, "expires_in");
        int interval = GetInt(root, "interval");
        if (!Code.IsMatch(device) || !UserCode.IsMatch(code) ||
            url != "https://github.com/login/device" ||
            expires is < 60 or > 1800 || interval is < 1 or > 60)
            throw new InvalidDataException("GitHub returned invalid device authorization details.");
        return new GitHubDeviceChallenge(clientId, device, code,
            new Uri(url), expires, interval);
    }

    internal async Task<string> WaitForAuthorizationAsync(GitHubDeviceChallenge challenge,
        Action<string>? updateStatus = null, CancellationToken cancellationToken = default)
    {
        if (!ReportingProviderIdentifiers.ValidClientId(challenge.ClientId) ||
            !Code.IsMatch(challenge.DeviceCode) ||
            !UserCode.IsMatch(challenge.UserCode) ||
            challenge.VerificationUri.AbsoluteUri != "https://github.com/login/device" ||
            challenge.ExpiresInSeconds is < 60 or > 1800 ||
            challenge.PollIntervalSeconds is < 1 or > 60)
            throw new InvalidDataException("Invalid GitHub device authorization session.");

        int interval = challenge.PollIntervalSeconds;
        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(challenge.ExpiresInSeconds);
        while (DateTimeOffset.UtcNow < deadline)
        {
            // GitHub requires waiting before FIRST and subsequent polls.
            await Task.Delay(TimeSpan.FromSeconds(interval), cancellationToken);
            if (DateTimeOffset.UtcNow >= deadline)
                break;
            using var form = new FormUrlEncodedContent(new Dictionary<string,string> {
                ["client_id"] = challenge.ClientId,
                ["device_code"] = challenge.DeviceCode,
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code"
            });
            using var json = await SendJsonAsync(TokenUrl, form, cancellationToken);
            var body = json.RootElement;
            if (body.TryGetProperty("access_token", out var tokenElement))
            {
                string accessToken = tokenElement.ValueKind == JsonValueKind.String
                    ? tokenElement.GetString() ?? "" : "";
                string tokenType = GetString(body, "token_type");
                string scopes = GetString(body, "scope");
                if (!Code.IsMatch(accessToken) ||
                    !tokenType.Equals("bearer", StringComparison.OrdinalIgnoreCase) ||
                    !scopes.Split(',', StringSplitOptions.TrimEntries)
                        .Contains("public_repo", StringComparer.Ordinal))
                    throw new InvalidDataException("GitHub OAuth token lacks the required public_repo scope.");
                return accessToken; // Caller never stores or logs it.
            }
            string error = GetString(body, "error");
            if (error == "authorization_pending")
            {
                updateStatus?.Invoke("Waiting for GitHub browser authorization...");
                continue;
            }
            if (error == "slow_down")
            {
                interval = Math.Min(120, Math.Max(interval + 5,
                    body.TryGetProperty("interval", out var extra) &&
                    extra.ValueKind == JsonValueKind.Number &&
                    extra.TryGetInt32(out int n) ? n : interval + 5));
                updateStatus?.Invoke("GitHub requested slower authentication polling.");
                continue;
            }
            if (error is "access_denied" or "expired_token" or "incorrect_device_code" or
                "device_flow_disabled" or "incorrect_client_credentials")
                throw new InvalidOperationException("GitHub device authorization failed: " + error);
            throw new InvalidOperationException("Unrecognized GitHub authorization response.");
        }
        throw new OperationCanceledException("GitHub device login expired. Connect again.");
    }

    private async Task<JsonDocument> SendJsonAsync(string destination, HttpContent content,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, destination) { Content = content };
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("TermsrvPatcherUnified", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await client.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.RequestMessage?.RequestUri?.AbsoluteUri != destination)
            throw new InvalidDataException("GitHub authentication unexpectedly changed destination.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException(
                $"GitHub authorization endpoint returned HTTP {(int)response.StatusCode}.");
        if (response.Content.Headers.ContentLength is > 8192)
            throw new InvalidDataException("GitHub authorization response is too large.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var data = new MemoryStream();
        byte[] buffer = new byte[1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (data.Length + read > 8192)
                throw new InvalidDataException("GitHub authorization response is too large.");
            data.Write(buffer, 0, read);
        }
        data.Position = 0;
        var parsed = await JsonDocument.ParseAsync(data, cancellationToken: ct);
        if (parsed.RootElement.ValueKind != JsonValueKind.Object)
        {
            parsed.Dispose();
            throw new InvalidDataException("GitHub authorization response is not an object.");
        }
        return parsed;
    }

    private static string GetString(JsonElement obj, string key) =>
        obj.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String
            ? item.GetString() ?? "" : "";

    private static int GetInt(JsonElement obj, string key) =>
        obj.TryGetProperty(key, out var value) &&
        value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int n) ? n : -1;

    public void Dispose()
    {
        if (ownsClient) client.Dispose();
    }
}