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


        // Structured system and offline reports use the same Google transport,
        // but require an explicitly verified GitHub Issue #1 comment receipt.
        var fix = new SuccessfulFixMetadata(
            "Windows 11", "26H2", 26300, 9711, "10.0.26100.9549",
            UpdateIntegration.Version, "automatic",
            new string('a', 64), new string('b', 64),
            [new ChangedBytes(0x00000220, "11223344", "AABBCCDD")]);
        var submission = CompatibilityRelaySubmission.Create(fix);
        Verify(submission.Kind == "successful_apply" &&
               submission.Json.Contains("termsrv-success/v2", StringComparison.Ordinal) &&
               !submission.Json.Contains("PRIVATE", StringComparison.Ordinal),
            "completed Apply produces exact bounded typed metadata without personal identifiers");


        // The combined manual report uses two existing strict Google schemas.
        // One human confirmation may authorize both, but it never upgrades
        // compatibility claims to verified remote RDP connectivity.
        var unified = new UnifiedApplyReport(fix);
        Verify(unified.DiagnosticJson.Contains("universal-diagnostics/v1",
                    StringComparison.Ordinal) &&
               unified.Compatibility.Kind == submission.Kind &&
               unified.Compatibility.Body == submission.Body &&
               unified.ReviewedText.Contains("1. GENERAL DIAGNOSTICS", StringComparison.Ordinal) &&
               unified.ReviewedText.Contains("2. DLL COMPATIBILITY", StringComparison.Ordinal) &&
               !unified.ReviewedText.Contains("PRIVATE", StringComparison.Ordinal),
               "one reviewed report holds two independent, validated public sections");
        const string generalReceipt =
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/987\"}";
        const string fixReceipt =
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1\"," +
            "\"comment_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1#issuecomment-6789\"}";
        var sent = new FakeHandler((request, payload) =>
        {
            if (request.Method != HttpMethod.Post ||
                request.RequestUri!.AbsoluteUri != deployed ||
                request.Headers.Authorization is not null)
                return Json("{\"ok\":false,\"error\":\"invalid_request\"}");
            return Json(payload.Contains("universal-diagnostics/v1", StringComparison.Ordinal)
                ? generalReceipt : fixReceipt);
        });
        using (var http = new HttpClient(sent))
        using (var client = new GoogleAppsScriptReportClient(http))
        {
            Uri diagnosticsUrl = client.SendAsync(deployed, unified.DiagnosticJson,
                unified.Diagnostics).GetAwaiter().GetResult();
            Uri compatibilityUrl = client.SendCompatibilityAsync(deployed,
                unified.Compatibility.Json, unified.Compatibility).GetAwaiter().GetResult();
            Verify(diagnosticsUrl.AbsoluteUri.EndsWith("/987", StringComparison.Ordinal) &&
                   compatibilityUrl.AbsoluteUri.EndsWith("#issuecomment-6789", StringComparison.Ordinal) &&
                   sent.Count == 2 && sent.Requests.All(r => !r.HasAuth) &&
                   sent.Requests[0].Body == unified.DiagnosticJson &&
                   sent.Requests[1].Body == unified.Compatibility.Json,
                "one approved unified review can submit exactly two separately acknowledged typed records");
        }
        const string consentSchema = "termsrv-auto-compatibility-consent/v1";
        var consentJson = JsonSerializer.Serialize(new {
            SchemaId = consentSchema,
            ReceiverSha256 = AutoCompatibilityReporting.ReceiverFingerprint(deployed),
            Enabled = true
        });
        Verify(AutoCompatibilityReporting.HasConsent(consentJson, deployed),
            "exact endpoint-bound machine-wide consent can authorize future silent reports");
        Verify(!AutoCompatibilityReporting.HasConsent(null, deployed) &&
               !AutoCompatibilityReporting.HasConsent(consentJson.Replace("true", "false"), deployed) &&
               !AutoCompatibilityReporting.HasConsent(consentJson, deployed + "?other=1") &&
               !AutoCompatibilityReporting.HasConsent(consentJson, "https://evil.example/exec") &&
               !AutoCompatibilityReporting.HasConsent(consentJson + "extra", deployed),
               "missing, disabled, corrupted or endpoint-mismatched consent fails closed");
        Verify(AutoCompatibilityReporting.CanAutoSend(true, true, PatchState.Ready,
                isManual: false, checksumVerified: true) &&
               !AutoCompatibilityReporting.CanAutoSend(false, true, PatchState.Ready,
                   isManual: false, checksumVerified: true) &&
               !AutoCompatibilityReporting.CanAutoSend(true, false, PatchState.Ready,
                   isManual: false, checksumVerified: true) &&
               !AutoCompatibilityReporting.CanAutoSend(true, true, PatchState.Ready,
                   isManual: true, checksumVerified: true) &&
               !AutoCompatibilityReporting.CanAutoSend(true, true, PatchState.AlreadyPatched,
                   isManual: false, checksumVerified: true) &&
               !AutoCompatibilityReporting.CanAutoSend(true, true, PatchState.Ready,
                   isManual: false, checksumVerified: false),
               "only a new verified automatic SYSTEM Apply with consent may silently report");


        // A Session 0 one-shot protected Apply can lose the interactive GUI
        // during TermService restart. Persisted verified report evidence must
        // agree with the exact request and CURRENT installed DLL before any
        // offer is shown. Automatic Windows-Update work has no such status.
        string completedId = Guid.NewGuid().ToString("N");
        var completedRequest = new IsolatedApplyExecutor.Request(
            completedId, fix.OriginalSha256, fix.PatchedSha256, fix.DllVersion,
            "synthetic-approved-profile", new string('c', 64), true);
        var completedStatus = new IsolatedApplyExecutor.Status(
            completedId, "Succeeded", "Protected write and RDP service recovery returned successfully.",
            DateTimeOffset.UtcNow.ToString("O"), fix);
        var persistedStatus = JsonSerializer.Deserialize<IsolatedApplyExecutor.Status>(
            JsonSerializer.Serialize(completedStatus));
        Verify(persistedStatus?.Report?.Changes.Count == 1 &&
               IsolatedApplyExecutor.VerifiedReportMatches(persistedStatus,
                   completedRequest, fix.PatchedSha256),
               "protected one-shot status survives full JSON roundtrip after GUI termination");
        Verify(IsolatedApplyExecutor.VerifiedReportMatches(completedStatus,
                   completedRequest, fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus,
                   completedRequest, fix.OriginalSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus with {
                   State = "AlreadyPatched" }, completedRequest, fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus with {
                   Report = null }, completedRequest, fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus with {
                   Id = Guid.NewGuid().ToString("N") }, completedRequest, fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus,
                   completedRequest with { OriginalSha256 = new string('d', 64) },
                   fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus,
                   completedRequest with { ExpectedPatchedSha256 = new string('e', 64) },
                   fix.PatchedSha256) &&
               !IsolatedApplyExecutor.VerifiedReportMatches(completedStatus,
                   completedRequest with { ExpectedPatchedSha256 = null! },
                   fix.PatchedSha256),
               "post-reconnect report requires exact one-shot ID, success, both hashes, and installed DLL");

        // The original queued EXE (not the new reporting GUI version) must
        // provide its authoritative informational ProductVersion.
        string appModule = typeof(TermsrvEngine).Assembly.Location;
        Verify(File.Exists(appModule) &&
               IsolatedApplyExecutor.VersionFromStagedExecutable(appModule) ==
                   UpdateIntegration.Version,
               "original signed-file metadata yields exact app version for recovered reports");

        // Actual Windows version resources include the WinBuild suffix:
        // Preview.3 persisted "Succeeded" but omitted Report when its strictly
        // numeric DLL metadata validator rejected this valid resource text.
        const string rawVersion = "10.0.26100.8115 (WinBuild.160101.0800)";
        const string numericVersion = "10.0.26100.8115";
        Verify(SuccessfulFixMetadata.CanonicalDllVersion(rawVersion) == numericVersion &&
               SuccessfulFixMetadata.CanonicalDllVersion(numericVersion) == numericVersion &&
               SuccessfulFixMetadata.CanonicalDllVersion("10.0.26100.8115 (winbuild.160101.0800)") ==
                   numericVersion &&
               SuccessfulFixMetadata.CanonicalDllVersion("10.0.26100.8115 (unknown)") is null &&
               SuccessfulFixMetadata.CanonicalDllVersion("not-a-version") is null &&
               SuccessfulFixMetadata.CanonicalDllVersion("10.0.26100.8115<script>") is null,
               "WinBuild resource suffix normalizes only to strict numeric DLL version");
        var rawPlan = new PatchPlan(PatchState.Ready, "synthetic", "synthetic-approved-profile",
            "C:\\Windows\\System32\\termsrv.dll", rawVersion,
            new string('a', 64),
            [new PatchEdit(0x220, [0x11, 0x22, 0x33, 0x44],
                                  [0xAA, 0xBB, 0xCC, 0xDD])],
            Enumerable.Repeat((byte)0x33, 1024).ToArray());
        var rawOS = new WindowsDetails("Windows 11", "26H2", 26300, 9711,
            "Client", true, "C:\\Windows\\System32\\termsrv.dll", rawVersion);
        var normalizedFix = SuccessfulFixMetadata.FromSuccessfulApply(rawOS, rawPlan);
        Verify(normalizedFix.DllVersion == numericVersion &&
               normalizedFix.AsComment().Contains("dll=" + numericVersion, StringComparison.Ordinal) &&
               !normalizedFix.AsComment().Contains("WinBuild", StringComparison.Ordinal),
               "post-Apply Google compatibility report omits WinBuild resource suffix");

        // Read-only recovery of a Preview.3 SYSTEM worker that wrote Succeeded
        // without a report. The authenticated recovery-journal boundary itself
        // is separately tested by RecoveryJournalStore; this test validates
        // the exact request, original/replacement bytes and current checksum.
        byte[] originalSynthetic = OfflineDllTests.SyntheticDll(x64: true);
        byte[] patchedSynthetic = (byte[])originalSynthetic.Clone();
        new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(patchedSynthetic, 0x220);
        var recoveryRequest = new IsolatedApplyExecutor.Request(
            completedId, SystemInfo.Sha256(originalSynthetic),
            SystemInfo.Sha256(patchedSynthetic), rawVersion,
            "synthetic-approved-profile", new string('c', 64), true);
        var recoveryStatus = new IsolatedApplyExecutor.Status(
            completedId, "Succeeded",
            "Protected write and RDP service recovery returned successfully.",
            DateTimeOffset.UtcNow.ToString("O"), Report: null);
        var recoveryJournal = new RecoveryJournalStore.Verified(
            recoveryRequest.OriginalSha256, recoveryRequest.ExpectedPatchedSha256,
            rawVersion, recoveryRequest.ProfileId, originalSynthetic,
            [new RecoveryJournalStore.Change(0x220,
                [0x11, 0x22, 0x33, 0x44], [0xAA, 0xBB, 0xCC, 0xDD])]);
        var recoveredMetadata = IsolatedApplyExecutor.RecoverFromVerifiedJournal(
            recoveryStatus, recoveryRequest, rawOS, patchedSynthetic,
            recoveryJournal, "1.0.5-preview.3");
        Verify(recoveredMetadata is not null &&
               recoveredMetadata.DllVersion == numericVersion &&
               recoveredMetadata.ApplicationVersion == "1.0.5-preview.3" &&
               recoveredMetadata.OriginalSha256 == recoveryRequest.OriginalSha256 &&
               recoveredMetadata.PatchedSha256 == recoveryRequest.ExpectedPatchedSha256 &&
               recoveredMetadata.Changes.Count == 1 &&
               recoveredMetadata.Changes[0].Offset == 0x220 &&
               recoveredMetadata.Changes[0].Before == "11223344" &&
               recoveredMetadata.Changes[0].After == "AABBCCDD" &&
               IsolatedApplyExecutor.VerifiedReportMatches(
                   recoveryStatus with { Report = recoveredMetadata },
                   recoveryRequest, recoveryRequest.ExpectedPatchedSha256),
               "Preview.3 one-shot success safely reconstructs a reviewed report without another Apply");
        var changedInstalled = (byte[])patchedSynthetic.Clone();
        changedInstalled[0x220] ^= 1;
        Verify(IsolatedApplyExecutor.RecoverFromVerifiedJournal(
                   recoveryStatus, recoveryRequest, rawOS, changedInstalled,
                   recoveryJournal, "1.0.5-preview.3") is null &&
               IsolatedApplyExecutor.RecoverFromVerifiedJournal(
                   recoveryStatus with { State = "AlreadyPatched" }, recoveryRequest, rawOS,
                   patchedSynthetic, recoveryJournal, "1.0.5-preview.3") is null &&
               IsolatedApplyExecutor.RecoverFromVerifiedJournal(
                   recoveryStatus with { Id = Guid.NewGuid().ToString("N") },
                   recoveryRequest, rawOS, patchedSynthetic, recoveryJournal,
                   "1.0.5-preview.3") is null &&
               IsolatedApplyExecutor.RecoverFromVerifiedJournal(
                   recoveryStatus, recoveryRequest with { OriginalSha256 = new string('d', 64) },
                   rawOS, patchedSynthetic, recoveryJournal, "1.0.5-preview.3") is null &&
               IsolatedApplyExecutor.RecoverFromVerifiedJournal(
                   recoveryStatus, recoveryRequest, rawOS, patchedSynthetic,
                   recoveryJournal with { ProfileId = "unapproved" },
                   "1.0.5-preview.3") is null,
               "recovered reports reject drift, stale tasks and mismatching protected evidence");

        var offline = new OfflineFixMetadata("x64", "10.0.26100.9549",
            UpdateIntegration.Version, new string('a', 64), "1234ABCD",
            new string('b', 64), "AABBCCDD",
            [new ChangedBytes(0x00000220, "11223344", "AABBCCDD")]);
        var offlineSubmission = CompatibilityRelaySubmission.Create(offline);
        Verify(offlineSubmission.Kind == "offline_file" &&
               offlineSubmission.Json.Contains("termsrv-offline/v1", StringComparison.Ordinal) &&
               !offlineSubmission.Json.Contains("termsrv-success/v2", StringComparison.Ordinal),
            "offline result cannot be relabeled as verified installed Apply");

        const string commentReceipt =
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1\"," +
            "\"comment_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1#issuecomment-1234\"}";
        var compatibilityHandler = new FakeHandler((_, _) => Json(commentReceipt));
        using (var http = new HttpClient(compatibilityHandler))
        using (var client = new GoogleAppsScriptReportClient(http))
        {
            Uri receiptUrl = client.SendCompatibilityAsync(
                deployed, submission.Json, submission).GetAwaiter().GetResult();
            Verify(receiptUrl.AbsoluteUri.EndsWith("#issuecomment-1234", StringComparison.Ordinal) &&
                   compatibilityHandler.Count == 1 && !compatibilityHandler.Requests[0].HasAuth &&
                   compatibilityHandler.Requests[0].Body == submission.Json,
                "public compatibility report sent once without a GitHub token");
            Throws<InvalidDataException>(() => client.SendCompatibilityAsync(
                deployed, submission.Json + " ", submission).GetAwaiter().GetResult(),
                "changed metadata cannot be sent after approval");
            Verify(compatibilityHandler.Count == 1,
                "mutated reviewed JSON never causes another request");
            Uri offlineReceipt = client.SendCompatibilityAsync(
                deployed, offlineSubmission.Json, offlineSubmission).GetAwaiter().GetResult();
            Verify(offlineReceipt.AbsoluteUri.EndsWith("#issuecomment-1234", StringComparison.Ordinal) &&
                   compatibilityHandler.Count == 2, "offline report uses identical consent-only endpoint");
        }
        foreach (var badReceipt in new[] {
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1\"}",
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1\"," +
                "\"comment_url\":\"https://evil.example/issues/1#issuecomment-12\"}",
            "{\"ok\":true,\"issue_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/2\"," +
                "\"comment_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/1#issuecomment-12\"}"
        })
        {
            var fake = new FakeHandler((_, _) => Json(badReceipt));
            using var http = new HttpClient(fake);
            using var client = new GoogleAppsScriptReportClient(http);
            Throws<InvalidDataException>(() => client.SendCompatibilityAsync(
                deployed, submission.Json, submission).GetAwaiter().GetResult(),
                "a generic Issue or an off-repository comment is not delivery confirmation");
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
