using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using UniversalDiagnostics.Transport;
using TermsrvPatcherUnified.Core;

internal static class DirectReportingTests
{
    private static int assertions;
    private static void Verify(bool value, string message)
    {
        assertions++;
        if (!value) throw new InvalidOperationException("Direct reporting QA: " + message);
    }

    private static void Throws<T>(Action action, string message) where T : Exception
    {
        bool failed = false;
        try { action(); } catch (T) { failed = true; }
        Verify(failed, message);
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, string, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        internal int Requests;
        internal string LastBody = "";
        internal Uri? LastUri;
        internal HttpMethod? LastMethod;
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            LastUri = request.RequestUri;
            LastMethod = request.Method;
            LastBody = request.Content is null ? "" :
                await request.Content.ReadAsStringAsync(cancellationToken);
            var response = respond(request, LastBody);
            response.RequestMessage = request;
            return response;
        }
    }

    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static AnonymousDiagnosticPayload Example()
    {
        const string project = "sgennadi/TermsrvPatcherUnified";
        const string component = "RdpSettings";
        const string type = "InvalidOperationException";
        const string code = "0x80131509";
        var signature = string.Join("|", new[] {project, component, type, code}
            .Select(x => x.ToLowerInvariant()));
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(signature)));
        var json = JsonSerializer.Serialize(new
        {
            @event = new
            {
                schema = "universal-diagnostics/v1",
                id = Guid.NewGuid().ToString("D"),
                timestamp_utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                project, component, error_type = type, code, level = "error",
                version = UpdateIntegration.Version, platform = "Windows", architecture = "AMD64",
                fingerprint, windows_release = "25H2", windows_build = 26200, windows_ubr = 1234,
                dll_version = "10.0.26200.1234", dll_sha256 = new string('a', 64)
            },
            summary = "HOSTNAME PRIVATE DATA MUST NEVER LEAK",
            delivery = new { status = "pending" }
        });
        return UniversalDiagnosticsRelayClient.Prepare(json);
    }

    internal static int Run()
    {
        var payload = Example();
        Verify(DirectReportingSettings.ValidFormId("mabc1234") &&
               !DirectReportingSettings.ValidFormId("x/../../secret") &&
               !DirectReportingSettings.ValidFormId("https://evil.example"),
            "form ID validation refuses arbitrary URLs and traversal");
        Verify(DirectReportingSettings.ValidClientId("Iv1.12345678") &&
               !DirectReportingSettings.ValidClientId("unsafe client id"),
            "OAuth client IDs are bounded and cannot contain whitespace");

        var endpoint = FormspreeReportClient.Endpoint("mabc1234");
        Verify(endpoint.AbsoluteUri == "https://formspree.io/f/mabc1234",
            "Formspree endpoint is pinned to official HTTPS host");
        var outgoing = FormspreeReportClient.BuildSubmission(payload, DiagnosticsBridge.Project);
        using (var doc = JsonDocument.Parse(outgoing))
        {
            var root = doc.RootElement;
            Verify(root.GetProperty("windows_build").GetInt32() == 26200 &&
                   root.GetProperty("dll_sha256").GetString() == new string('a', 64),
                "typed optional DLL evidence preserved");
            Verify(!root.TryGetProperty("summary", out _) &&
                   !root.TryGetProperty("delivery", out _) &&
                   !outgoing.Contains("HOSTNAME PRIVATE DATA", StringComparison.Ordinal),
                "raw summary and local queue are never shared with Formspree");
        }

        var success = new FakeHandler((_, _) => Ok("{\"ok\":true}"));
        using (var http = new HttpClient(success))
        using (var client = new FormspreeReportClient(http))
        {
            client.SendAsync("mabc1234", outgoing, payload, DiagnosticsBridge.Project).GetAwaiter().GetResult();
            Verify(success.Requests == 1 && success.LastUri == endpoint &&
                   success.LastMethod == HttpMethod.Post,
                "Formspree receives exactly one POST to pinned endpoint");
            Verify(success.LastBody == outgoing && !success.LastBody.Contains("HOSTNAME PRIVATE DATA"),
                "Formspree receives exact reviewed JSON only");
            Throws<InvalidDataException>(() =>
                client.SendAsync("mabc1234", outgoing + " ", payload, DiagnosticsBridge.Project).GetAwaiter().GetResult(),
                "reviewed Formspree JSON cannot change before dispatch");
            Verify(success.Requests == 1, "modified payload rejected before HTTP");
        }

        foreach (var (code, json) in new[] {
            (HttpStatusCode.OK, "{\"ok\":false}"),
            (HttpStatusCode.Forbidden, "{\"ok\":true}"),
            (HttpStatusCode.Redirect, "{\"ok\":true}")
        })
        {
            var handler = new FakeHandler((_, _) => new HttpResponseMessage(code) {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
            using var http = new HttpClient(handler);
            using var client = new FormspreeReportClient(http);
            bool denied = false;
            try { client.SendAsync("mabc1234", outgoing, payload, DiagnosticsBridge.Project).GetAwaiter().GetResult(); }
            catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException)
            { denied = true; }
            Verify(denied && handler.Requests == 1,
                "Formspree status or JSON confirmation is required");
        }

        var github = new FakeHandler((request, body) => request.RequestUri!.AbsoluteUri switch
        {
            "https://github.com/login/device/code" =>
                Ok("{\"device_code\":\"" + new string('a', 40) +
                   "\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://github.com/login/device\"," +
                   "\"expires_in\":120,\"interval\":1}"),
            "https://github.com/login/oauth/access_token" =>
                Ok("{\"access_token\":\"gho_" + new string('b', 36) +
                   "\",\"token_type\":\"bearer\",\"scope\":\"public_repo\"}"),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        });
        using (var http = new HttpClient(github))
        using (var auth = new GitHubDeviceAuthorization(http))
        {
            var challenge = auth.RequestCodeAsync("Iv1.12345678").GetAwaiter().GetResult();
            Verify(challenge.UserCode == "WDJB-MJHT" &&
                   challenge.VerificationUri.AbsoluteUri == "https://github.com/login/device" &&
                   github.Requests == 1,
                "GitHub code request returns only official browser URL");
            Verify(github.LastBody.Contains("scope=public_repo", StringComparison.Ordinal) &&
                   github.LastBody.Contains("client_id=Iv1.12345678", StringComparison.Ordinal),
                "GitHub requests only public repository scope");
            string token = auth.WaitForAuthorizationAsync(challenge).GetAwaiter().GetResult();
            Verify(token.StartsWith("gho_", StringComparison.Ordinal) && github.Requests == 2 &&
                   github.LastUri?.AbsoluteUri == "https://github.com/login/oauth/access_token" &&
                   github.LastBody.Contains("device_code=", StringComparison.Ordinal) &&
                   !github.LastBody.Contains("client_secret", StringComparison.Ordinal),
                "browser-authorized token returned in memory without client secret");
        }

        // Missing Formspree and OAuth IDs must fail closed; these are not built-in credentials.
        var oldState = Environment.GetEnvironmentVariable("UDX_STATE_DIR");
        var temp = Path.Combine(Path.GetTempPath(), "TermsrvDirectQA-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("UDX_STATE_DIR", temp);
            var receipt = DiagnosticsBridge.Capture(
                new DiagnosticsBridge.DiagnosticDraft("Test", "USER_REPORT", "TEST", "Test"),
                "Synthetic and sanitized report");
            DiagnosticsBridge.MarkFormspreeSubmitted(receipt.Path, receipt.Id, "mabc1234");
            using var doc = JsonDocument.Parse(File.ReadAllText(receipt.Path));
            var delivery = doc.RootElement.GetProperty("delivery");
            Verify(delivery.GetProperty("status").GetString() == "submitted" &&
                   delivery.GetProperty("provider").GetString() == "formspree" &&
                   delivery.GetProperty("form_id").GetString() == "mabc1234" &&
                   delivery.GetProperty("url").ValueKind == JsonValueKind.Null,
                "Formspree receipt does not claim a GitHub Issue URL");
            Throws<InvalidOperationException>(() =>
                DiagnosticsBridge.MarkFormspreeSubmitted(receipt.Path, receipt.Id, "mabc1234"),
                "an acknowledged receipt cannot be recorded twice");
        }
        finally
        {
            Environment.SetEnvironmentVariable("UDX_STATE_DIR", oldState);
            if (Directory.Exists(temp)) Directory.Delete(temp, recursive: true);
        }
        Console.WriteLine("PASS: " + assertions +
            " receiver-free provider, privacy, OAuth, Formspree and queue tests (stub HTTP)");
        return assertions;
    }
}