// Canonical reusable .NET 8+ client for UniversalDiagnostics v1.
// Send only typed allowlisted metadata, never summary, credentials, logs or stack traces.
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UniversalDiagnostics.Transport;

public sealed record AnonymousDiagnosticPayload(string EventId, string Project, string Json);

public sealed class UniversalDiagnosticsRelayClient : IDisposable
{
    private const string Schema = "universal-diagnostics/v1";
    private const string ReceiptSchema = "universal-diagnostics-relay/v1";
    private readonly HttpClient client;
    private readonly bool ownsClient;

    public UniversalDiagnosticsRelayClient(HttpClient? injectedClient = null)
    {
        ownsClient = injectedClient is null;
        client = injectedClient ?? new HttpClient(new HttpClientHandler {
            AllowAutoRedirect = false, UseCookies = false
        }) { Timeout = TimeSpan.FromSeconds(25) };
    }

    public static Uri? ReadConfiguredEndpoint()
    {
        var location = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.CommonApplicationData), "UniversalDiagnostics", "relay.json");
        if (!File.Exists(location)) return null;
        using var doc = JsonDocument.Parse(File.ReadAllText(location));
        if (!doc.RootElement.TryGetProperty("endpoint", out var value) ||
            value.ValueKind != JsonValueKind.String ||
            !Uri.TryCreate(value.GetString(), UriKind.Absolute, out var uri) ||
            !IsApprovedEndpoint(uri))
            throw new InvalidDataException("UniversalDiagnostics relay.json has an invalid HTTPS endpoint.");
        return uri;
    }

    public static bool IsApprovedEndpoint(Uri? uri) => uri is not null &&
        uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.HostNameType == UriHostNameType.Dns &&
        !uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
        !uri.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        uri.AbsolutePath == "/v1/diagnostics";

    private static string Field(JsonElement e, string name)
    {
        if (!e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Missing diagnostic field: " + name);
        return v.GetString()!;
    }

    private static string Match(string value, string regex, string name)
    {
        if (!Regex.IsMatch(value, regex, RegexOptions.CultureInvariant))
            throw new InvalidDataException("Unsafe diagnostic field: " + name);
        return value;
    }

    public static AnonymousDiagnosticPayload Prepare(string localRecord)
    {
        using var doc = JsonDocument.Parse(localRecord);
        var e = doc.RootElement.GetProperty("event");
        var schema = Field(e, "schema");
        var id = Field(e, "id");
        var project = Match(Field(e, "project"), @"^sgennadi/[A-Za-z0-9_.-]{2,80}$", "project");
        var component = Match(Field(e, "component"), @"^[A-Za-z][A-Za-z0-9 _-]{0,55}$", "component");
        var type = Match(Field(e, "error_type"), @"^[A-Za-z][A-Za-z0-9_]{0,63}$", "error_type");
        var code = Match(Field(e, "code"), @"^(?:0x[A-Fa-f0-9]{1,8}|[A-Za-z0-9_-]{1,32})$", "code");
        var level = Field(e, "level");
        var version = Match(Field(e, "version"), @"^[A-Za-z0-9][A-Za-z0-9+._-]{0,49}$", "version");
        var platform = Field(e, "platform");
        var architecture = Field(e, "architecture");
        var timestamp = Field(e, "timestamp_utc");
        var fingerprint = Field(e, "fingerprint");
        if (schema != Schema || !Guid.TryParseExact(id, "D", out _) ||
            !new[] {"error","warning","info"}.Contains(level) ||
            !new[] {"Windows","Linux","macOS","Other"}.Contains(platform) ||
            !new[] {"AMD64","x86","ARM64","Other"}.Contains(architecture) ||
            !DateTime.TryParseExact(timestamp, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out _))
            throw new InvalidDataException("Invalid anonymous diagnostics metadata.");
        var source = string.Join("|", new[] {project,component,type,code}.Select(s => s.ToLowerInvariant()));
        var expected = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(source)));
        if (fingerprint != expected) throw new InvalidDataException("Diagnostic fingerprint mismatch.");
        // Optional Termsrv-only evidence is exact, all-or-nothing and typed.
        // This is an extension of v1, not a new endpoint or a free-text channel.
        const string termsrvProject = "sgennadi/TermsrvPatcherUnified";
        var additional = new[] { "windows_release", "windows_build", "windows_ubr",
                                 "dll_version", "dll_sha256" };
        int present = additional.Count(k => e.TryGetProperty(k, out _));
        if (present != 0 && (project != termsrvProject || present != additional.Length))
            throw new InvalidDataException("Incomplete or unauthorized DLL evidence.");
        var outgoing = new Dictionary<string, object> {
            ["schema"] = schema, ["id"] = id, ["timestamp_utc"] = timestamp,
            ["project"] = project, ["component"] = component,
            ["error_type"] = type, ["code"] = code, ["level"] = level,
            ["version"] = version, ["platform"] = platform,
            ["architecture"] = architecture, ["fingerprint"] = fingerprint
        };
        if (present == additional.Length)
        {
            string release = Match(Field(e, "windows_release"),
                @"^[A-Za-z0-9._-]{1,20}$", "windows_release");
            string dllVersion = Match(Field(e, "dll_version"),
                @"^[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}$", "dll_version");
            string dllSha = Match(Field(e, "dll_sha256"),
                @"^[a-f0-9]{64}$", "dll_sha256");
            if (!e.TryGetProperty("windows_build", out var build) ||
                build.ValueKind != JsonValueKind.Number || !build.TryGetInt32(out int buildNumber) ||
                buildNumber is < 19041 or > 99999 ||
                !e.TryGetProperty("windows_ubr", out var ubr) ||
                ubr.ValueKind != JsonValueKind.Number || !ubr.TryGetInt32(out int ubrNumber) ||
                ubrNumber is < 0 or > 999999)
                throw new InvalidDataException("Invalid DLL build metadata.");
            outgoing["windows_release"] = release;
            outgoing["windows_build"] = buildNumber;
            outgoing["windows_ubr"] = ubrNumber;
            outgoing["dll_version"] = dllVersion;
            outgoing["dll_sha256"] = dllSha;
        }
        var output = JsonSerializer.Serialize(new { @event = outgoing },
            new JsonSerializerOptions {WriteIndented = true});
        if (Encoding.UTF8.GetByteCount(output) > 8192)
            throw new InvalidDataException("Anonymous report too large.");
        return new AnonymousDiagnosticPayload(id, project, output);
    }

    public static bool IsApprovedIssueUri(Uri? uri, string project) =>
        uri is not null && uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort &&
        uri.UserInfo.Length == 0 && uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        Regex.IsMatch(Uri.UnescapeDataString(uri.AbsolutePath),
            "^/" + Regex.Escape(project) + @"/issues/[1-9][0-9]*$", RegexOptions.CultureInvariant);

    public async Task<Uri> SendAsync(AnonymousDiagnosticPayload payload, Uri endpoint,
        CancellationToken cancellationToken = default)
    {
        if (!IsApprovedEndpoint(endpoint)) throw new ArgumentException("Invalid HTTPS relay endpoint.");
        var verified = Prepare(payload.Json);
        if (verified.EventId != payload.EventId || verified.Project != payload.Project ||
            verified.Json != payload.Json) throw new InvalidDataException("Report changed after review.");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.UserAgent.ParseAdd("UniversalDiagnostics/1.0");
        request.Content = new StringContent(payload.Json, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri?.AbsoluteUri != endpoint.AbsoluteUri)
            throw new InvalidDataException("Relay endpoint changed unexpectedly.");
        if (response.StatusCode != HttpStatusCode.Created && response.StatusCode != HttpStatusCode.OK)
            throw new InvalidOperationException("Delivery not confirmed (HTTP " +
                (int)response.StatusCode + "). Local report remains pending.");
        if (response.Content.Headers.ContentLength > 16384)
            throw new InvalidDataException("Oversized relay confirmation.");
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var limited = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (limited.Length + count > 16384) throw new InvalidDataException("Oversized relay confirmation.");
            limited.Write(buffer, 0, count);
        }
        using var confirmation = JsonDocument.Parse(limited.ToArray());
        var root = confirmation.RootElement;
        if (Field(root, "schema") != ReceiptSchema ||
            Field(root, "id") != payload.EventId ||
            Field(root, "project") != payload.Project ||
            Field(root, "status") != "submitted" ||
            !Uri.TryCreate(Field(root, "issue_url"), UriKind.Absolute, out var issue) ||
            !IsApprovedIssueUri(issue, payload.Project))
            throw new InvalidDataException("Untrusted relay receipt.");
        return issue;
    }

    public void Dispose() { if (ownsClient) client.Dispose(); }
}
