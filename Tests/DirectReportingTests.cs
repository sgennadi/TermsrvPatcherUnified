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
    private static void Verify(bool condition, string reason)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException("Google reporting QA: " + reason);
    }

    private static void Throws<T>(Action action, string reason) where T : Exception
    {
        bool rejected = false;
        try { action(); } catch (T) { rejected = true; }
        Verify(rejected, reason);
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, string, HttpResponseMessage> reply)
        : HttpMessageHandler
    {
        internal int Count;
        internal readonly List<(Uri Uri, HttpMethod Method, string Body, bool HasAuth)> Requests = [];
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken token)
        {
            string body = request.Content is null ? "" :
                await request.Content.ReadAsStringAsync(token);
            Count++;
            Requests.Add((request.RequestUri!, request.Method, body,
                request.Headers.Authorization is not null));
            var response = reply(request, body);
            response.RequestMessage = request;
            return response;
        }
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static AnonymousDiagnosticPayload Example()
    {
        const string project = "sgennadi/TermsrvPatcherUnified";
        const string component = "RdpSettings";
        const string type = "InvalidOperationException";
        const string code = "0x80131509";
        var parts = new[] { project, component, type, code };
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(string.Join("|", parts.Select(x => x.ToLowerInvariant())))));
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
            summary = "PRIVATE MACHINE NAME NOT TRANSMITTED"
        });
        return UniversalDiagnosticsRelayClient.Prepare(json);
    }

    internal static int Run()
    {
        var settings = DirectReportingSettings.Load();
        const string deployed = "https://script.google.com/macros/s/AKfycbyV-tq5tMa08XaEmgo6-vpHD6ISQGOci32oPjy5ELm2pHUAud_Wn5j5YjVV0kcc6o62/exec";
        Verify(GoogleAppsScriptReportClient.IsApprovedEndpoint(deployed),
            "exact approved Google deployment URL");
        Verify(!GoogleAppsScriptReportClient.IsApprovedEndpoint("http://script.google.com/macros/s/AKfycbyVxxxxxxxxxxxxxxxxxxxxxxxx/exec"),
            "HTTP endpoint is rejected");
        Verify(!GoogleAppsScriptReportClient.IsApprovedEndpoint("https://evil.example/macros/s/AKfycbyVxxxxxxxxxxxxxxxxxxxxxxxx/exec"),
            "non-Google endpoint is rejected");
        Verify(!GoogleAppsScriptReportClient.IsApprovedEndpoint(deployed + "?token=NOT_ALLOWED"),
            "Google endpoint cannot contain query secrets");
        Verify(!GoogleAppsScriptReportClient.IsApprovedEndpoint("https://formspree.io/f/mvkkernb"),
            "obsolete Formspree cannot be configured as Google provider");
        var parsed = DirectReportingSettings.Parse(
            JsonSerializer.Serialize(new Dictionary<string, string> {
                ["google_apps_script_url"] = deployed, ["github_oauth_client_id"] = ""
            }));
        Verify(parsed.HasGoogleScript && !parsed.HasGitHubOAuth &&
               parsed.GoogleAppsScriptUrl == deployed, "embedded Google endpoint loads without OAuth");
        Throws<InvalidDataException>(() => DirectReportingSettings.Parse(
            "{\"formspree_form_id\":\"mvkkernb\"}"),
            "legacy Formspree key explicitly rejected");
        Throws<InvalidDataException>(() => DirectReportingSettings.Parse(
            "{\"google_apps_script_url\":\"https://evil.example/exec\"}"),
            "unsafe embedded Google destination rejected");
        Throws<InvalidDataException>(() => DirectReportingSettings.Parse(
            "{\"github_oauth_client_id\":\"\", \"secret\":\"DO_NOT_EMBED\"}"),
            "unknown fields and tokens cannot be embedded");
        Throws<InvalidDataException>(() => DirectReportingSettings.Parse(
            "{\"google_apps_script_url\":\"\",\"google_apps_script_url\":\"\"}"),
            "duplicate configuration keys rejected");
        if (string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true",
                StringComparison.OrdinalIgnoreCase))
        {
            Verify(settings.HasGoogleScript && settings.GoogleAppsScriptUrl == deployed,
                "GitHub Actions EXE embeds supplied Google deployment URL");
            Verify(typeof(DirectReportingSettings).Assembly.GetManifestResourceNames()
                .Contains(DirectReportingSettings.ResourceName, StringComparer.Ordinal),
                "built-in executable resource is present");
        }

        var payload = Example();
        string body = GoogleAppsScriptReportClient.BuildSubmission(payload);
        Verify(!body.Contains("PRIVATE MACHINE NAME", StringComparison.Ordinal) &&
               !body.Contains("formspree", StringComparison.OrdinalIgnoreCase),
            "outgoing JSON excludes free text and the old destination");
        using (var doc = JsonDocument.Parse(body))
        {
            var e = doc.RootElement.GetProperty("event");
            Verify(e.GetProperty("windows_build").GetInt32() == 26200 &&
                   e.GetProperty("dll_sha256").GetString() == new string('a', 64) &&
                   !doc.RootElement.TryGetProperty("summary", out _),
                "typed Windows build and DLL SHA-256 included without raw summary");
        }

        var direct = DiagnosticsBridge.PrepareDirect(
            new DiagnosticsBridge.DiagnosticDraft(
                "Protected Apply", "VerifiedSuccess", "SUCCESS", "USER'S PRIVATE NOTES"),
            new DiagnosticEnvironment("25H2", 26200, 1234,
                "10.0.26200.1234", new string('a', 64)));
        string prepared = GoogleAppsScriptReportClient.BuildSubmission(direct);
        Verify(prepared.Contains("\"level\": \"info\"") &&
               !prepared.Contains("PRIVATE NOTES"),
            "verified successful Apply yields sanitized info report");
        var minimal = DiagnosticsBridge.PrepareDirect(
            new DiagnosticsBridge.DiagnosticDraft("Application", "USER_REPORT", "MANUAL", "PRIVATE"));
        Throws<InvalidDataException>(() => GoogleAppsScriptReportClient.BuildSubmission(minimal),
            "unchecked DLL evidence is not silently substituted or invented");

        const string receipt = "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1234\"}";
        var handler = new FakeHandler((req, _) =>
        {
            if (req.Method == HttpMethod.Post)
            {
                var redirect = Json("", HttpStatusCode.Found);
                redirect.Headers.Location = new Uri("https://script.googleusercontent.com/macros/echo?user_content_key=test_receipt&lib=example");
                return redirect;
            }
            return Json(receipt);
        });
        using (var http = new HttpClient(handler))
        using (var client = new GoogleAppsScriptReportClient(http))
        {
            var confirmed = client.SendAsync(deployed, body, payload).GetAwaiter().GetResult();
            Verify(confirmed.AbsoluteUri == "https://github.com/sgennadi/TermsrvPatcherUnified/issues/1234",
                "only confirmed repository Issue becomes successful delivery");
            Verify(handler.Count == 2 && handler.Requests[0].Method == HttpMethod.Post &&
                   handler.Requests[0].Uri.AbsoluteUri == deployed &&
                   handler.Requests[1].Method == HttpMethod.Get &&
                   handler.Requests[1].Uri.Host == "script.googleusercontent.com",
                "exactly one POST, then Google receipt GET (no second POST)");
            Verify(!handler.Requests.Any(x => x.HasAuth) &&
                   handler.Requests[1].Body.Length == 0,
                "no credentials or diagnostic bytes sent to redirected response host");
            Verify(handler.Requests[0].Body == body,
                "the only POST carries the exact reviewed payload");
            Throws<InvalidDataException>(() =>
                client.SendAsync(deployed, body + " ", payload).GetAwaiter().GetResult(),
                "changed report refused without network transmission");
            Verify(handler.Count == 2, "mutated payload does not cause an extra request");
        }

        var malicious = new FakeHandler((_, _) =>
        {
            var redirect = Json("", HttpStatusCode.Found);
            redirect.Headers.Location = new Uri("https://attacker.example/macros/echo?user_content_key=exfil");
            return redirect;
        });
        using (var http = new HttpClient(malicious))
        using (var client = new GoogleAppsScriptReportClient(http))
        {
            Throws<InvalidDataException>(() =>
                client.SendAsync(deployed, body, payload).GetAwaiter().GetResult(),
                "off-host redirect refused");
            Verify(malicious.Count == 1, "no redirect follow to unknown host");
        }

        foreach (string response in new [] {
            "{\"ok\":false,\"error\":\"github_not_confirmed\"}",
            "{\"ok\":true,\"issue_url\":\"https://evil.example/issues/1234\"}",
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/OtherRepo/issues/4\"}",
            "{\"ok\":true}",
            "invalid json"
        })
        {
            var fake = new FakeHandler((_, _) => Json(response));
            using var http = new HttpClient(fake);
            using var client = new GoogleAppsScriptReportClient(http);
            bool failed = false;
            try { client.SendAsync(deployed, body, payload).GetAwaiter().GetResult(); }
            catch (Exception ex) when (ex is InvalidDataException or InvalidOperationException or JsonException)
            { failed = true; }
            Verify(failed && fake.Count == 1,
                "unconfirmed, malicious or invalid JSON response never marks report delivered");
        }

        var github = new FakeHandler((request, _) => request.RequestUri!.AbsoluteUri switch
        {
            "https://github.com/login/device/code" =>
                Json("{\"device_code\":\"" + new string('a',40) +
                     "\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://github.com/login/device\"," +
                     "\"expires_in\":120,\"interval\":1}"),
            "https://github.com/login/oauth/access_token" =>
                Json("{\"access_token\":\"gho_" + new string('b',36) +
                     "\",\"token_type\":\"bearer\",\"scope\":\"public_repo\"}"),
            _ => Json("{}", HttpStatusCode.NotFound)
        });
        using (var http = new HttpClient(github))
        using (var oauth = new GitHubDeviceAuthorization(http))
        {
            var code = oauth.RequestCodeAsync("Iv1.12345678").GetAwaiter().GetResult();
            Verify(code.UserCode == "WDJB-MJHT" && github.Count == 1,
                "optional GitHub OAuth still accepts device-flow challenge");
            string token = oauth.WaitForAuthorizationAsync(code).GetAwaiter().GetResult();
            Verify(token.StartsWith("gho_", StringComparison.Ordinal) &&
                   !github.Requests.Any(x => x.HasAuth),
                "device-flow token exists only in memory");
        }
        Console.WriteLine("PASS: " + assertions + " Google-to-GitHub, consent-data, redirect, " +
            "receipt, configuration and OAuth synthetic tests; no live report sent.");
        return assertions;
    }
}
