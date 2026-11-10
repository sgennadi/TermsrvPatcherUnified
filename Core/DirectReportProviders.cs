using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using UniversalDiagnostics.Transport;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Optional, public *identifiers* for two receiver-free transports.
/// No access tokens, credentials, user identities, paths or passwords are saved.
/// Values may also be provided directly in the Diagnostics UI for one session.
/// </summary>
internal sealed record DirectReportingSettings(string FormspreeFormId, string GitHubOAuthClientId)
{
    private static readonly Regex FormId = new(
        @"\A[A-Za-z0-9]{6,40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex ClientId = new(
        @"\A[A-Za-z0-9._-]{8,100}\z", RegexOptions.CultureInvariant);

    internal static bool ValidFormId(string? id) => FormId.IsMatch(id ?? "");
    internal static bool ValidClientId(string? id) => ClientId.IsMatch(id ?? "");

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

/// <summary>
/// Formspree receives only the canonical, strictly typed anonymous metadata.
/// A 2xx alone is insufficient to mark delivery: Formspree must return ok=true.
/// Form submissions do NOT create GitHub Issues or update GitHub's CSV.
/// </summary>
internal sealed class FormspreeReportClient : IDisposable
{
    private readonly HttpClient http;
    private readonly bool ownsHttp;

    internal FormspreeReportClient(HttpClient? injectedClient = null)
    {
        http = injectedClient ?? new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(25) };
        ownsHttp = injectedClient is null;
    }

    internal static Uri Endpoint(string formId)
    {
        if (!DirectReportingSettings.ValidFormId(formId))
            throw new ArgumentException("Configure a valid Formspree form ID (letters and digits).");
        return new Uri("https://formspree.io/f/" + formId);
    }

    internal static string BuildSubmission(AnonymousDiagnosticPayload payload)
    {
        var verified = UniversalDiagnosticsRelayClient.Prepare(payload.Json);
        if (verified.EventId != payload.EventId || verified.Project != payload.Project ||
            verified.Json != payload.Json || payload.Project != DiagnosticsBridge.Project)
            throw new InvalidDataException("Reviewed diagnostic metadata was changed.");
        using var doc = JsonDocument.Parse(verified.Json);
        var eventObject = doc.RootElement.GetProperty("event");
        var data = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var field in eventObject.EnumerateObject())
        {
            if (field.Value.ValueKind == JsonValueKind.String)
                data.Add(field.Name, field.Value.GetString()!);
            else if (field.Value.ValueKind == JsonValueKind.Number &&
                     field.Name is "windows_build" or "windows_ubr")
                data.Add(field.Name, field.Value.GetInt32());
            else
                throw new InvalidDataException("Unsupported Formspree diagnostic field type.");
        }
        string result = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        if (Encoding.UTF8.GetByteCount(result) > 8192)
            throw new InvalidDataException("Formspree metadata exceeds 8192 bytes.");
        return result;
    }

    internal async Task SendAsync(string formId, string reviewedPayload,
        AnonymousDiagnosticPayload payload, CancellationToken ct = default)
    {
        var endpoint = Endpoint(formId);
        if (!string.Equals(reviewedPayload, BuildSubmission(payload), StringComparison.Ordinal))
            throw new InvalidDataException("Formspree payload changed after review.");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("TermsrvPatcherUnified", "0.1"));
        request.Content = new StringContent(reviewedPayload, Encoding.UTF8, "application/json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.RequestMessage?.RequestUri?.AbsoluteUri != endpoint.AbsoluteUri)
            throw new InvalidDataException("Unexpected Formspree destination.");
        if (response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Created))
            throw new InvalidOperationException(
                $"Formspree did not confirm the submission (HTTP {(int)response.StatusCode}).");
        if (response.Content.Headers.ContentLength is > 8192)
            throw new InvalidDataException("Formspree confirmation exceeds size limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var bounded = new MemoryStream();
        byte[] buffer = new byte[2048];
        int count;
        while ((count = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (bounded.Length + count > 8192)
                throw new InvalidDataException("Formspree confirmation exceeds size limit.");
            bounded.Write(buffer, 0, count);
        }
        bounded.Position = 0;
        using var doc = JsonDocument.Parse(bounded);
        if (doc.RootElement.ValueKind != JsonValueKind.Object ||
            !doc.RootElement.TryGetProperty("ok", out var ok) ||
            ok.ValueKind != JsonValueKind.True)
            throw new InvalidDataException(
                "Formspree did not return ok=true; check your Formspree dashboard before retrying.");
    }

    public void Dispose()
    {
        if (ownsHttp) http.Dispose();
    }
}