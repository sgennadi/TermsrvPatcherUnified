using UniversalDiagnostics.Transport;
using System.IO;
using System.Buffers.Binary;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TermsrvPatcherUnified.Core;

if (args is ["--pattern-inspection-qa"])
{
    Environment.ExitCode = PatternInspectionTests.Run() >= 35 ? 0 : 2;
    return;
}

if (args is ["--rdp-transaction-qa"])
{
    Environment.ExitCode = RdpTransactionTests.Run() >= 20 ? 0 : 2;
    return;
}

if (args is ["--rdp-policy-history-qa"])
{
    Environment.ExitCode = RdpPolicyHistoryTests.Run() >= 20 ? 0 : 2;
    return;
}

if (args is ["--rdp-health-qa"])
{
    Environment.ExitCode = RdpHealthTests.Run() >= 12 ? 0 : 2;
    return;
}

if (args is ["--offline-dll-qa"])
{
    Environment.ExitCode = OfflineDllTests.Run() >= 20 ? 0 : 2;
    return;
}

if (args is ["--operation-lock-qa"])
{
    Environment.ExitCode = OperationLockTests.Run() is 0 or >= 3 ? 0 : 2;
    return;
}

if (args is ["--dll-backup-qa"])
{
    Environment.ExitCode = DllBackupIntegrityTests.Run() >= 20 ? 0 : 2;
    return;
}

if (args is ["--published-upgrade-check", var oldZip, var newZip, var oldVersion, var newVersion])
{
    Environment.ExitCode = PublishedUpgradeTests.Run(oldZip, newZip, oldVersion, newVersion) == 3 ? 0 : 2;
    return;
}

if (args is ["--ui-smoke"])
{
    Environment.ExitCode = UiSmokeTests.Run() >= 20 ? 0 : 2;
    return;
}

int assertions = 0;
void Ensure(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception("FAILED: " + message);
}

void Expect<TException>(Action action, string message) where TException : Exception
{
    bool threw = false;
    try { action(); }
    catch (TException) { threw = true; }
    Ensure(threw, message);
}

byte[] FakeBytes(BytePattern group, int offset = 40)
{
    var value = Enumerable.Repeat((byte)0xFA, 256).ToArray();
    for (int i = 0; i < group.Search.Length; i++)
        value[offset + i] = group.Search[i] ?? 0x73;
    return value;
}

// Preview.22: pure policy regression checks, no protected file writes.
var syntheticOriginalSha = new string('a', 64);
var syntheticPatchedSha = new string('b', 64);
Ensure(!System32BackupStore.NeedsRefresh(syntheticOriginalSha, syntheticOriginalSha),
    "same original DLL does not overwrite .bak");
Ensure(System32BackupStore.NeedsRefresh(syntheticOriginalSha, syntheticPatchedSha),
    "changed Windows Update DLL requires archived old .bak and new verified copy");
Ensure(System32BackupStore.NeedsRefresh(syntheticOriginalSha, null),
    "missing .bak is eligible for first full backup");
var recoveryApproval = new AutomaticRevertPlan(syntheticOriginalSha,
    syntheticPatchedSha, "10.0.26100.1", "Generic", "Journal");
Ensure(AutomaticRevertSafety.SameApproval(recoveryApproval, recoveryApproval),
    "Revert approval is stable only for identical SHA-bound metadata");
Ensure(!AutomaticRevertSafety.SameApproval(recoveryApproval,
        recoveryApproval with { InstalledSha256 = new string('c', 64) }),
    "Windows Update invalidates previous Revert approval");
Ensure(!AutomaticRevertSafety.SameApproval(recoveryApproval,
        recoveryApproval with { RecoverySource = "System32Backup" }),
    "switching a Revert recovery source requires fresh confirmation");
Ensure(!AutomaticRevertSafety.SameApproval(recoveryApproval, null),
    "missing protected recovery record fails closed");
Ensure(IsolatedApplyExecutor.TryNormalizeId(Guid.NewGuid().ToString("N"), out _),
    "one-shot scheduled recovery identifier accepted");
Ensure(!IsolatedApplyExecutor.TryNormalizeId("../../System32", out _),
    "untrusted scheduled recovery identifier refused");
var signature = new BytePattern("11 * 33 44", "90 90 90 90");
var bytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44 };
Ensure(BytePattern.FindOffsets(bytes, signature.Search).SequenceEqual([1]), "wildcard matches");
Ensure(BytePattern.FindOffsets(new byte[] { 0x11, 0x55, 0x33, 0x44 }, signature.Search).SequenceEqual([0]),
    "matches last possible offset");
Ensure(BytePattern.FindOffsets(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44 },
    signature.Search).Count == 2, "ambiguous repeated signature");
Ensure(BytePattern.FindOffsets(bytes, signature.Search, 0).Count == 0, "max results limit");
Expect<FormatException>(() => BytePattern.ParseFind("A B C D"), "reject single hex digits");
Expect<FormatException>(() => BytePattern.ParseReplace("ZZ 11 22 33"), "reject invalid HEX");
Expect<ArgumentException>(() => new BytePattern("* * * *", "11 22 33 44"), "reject all wildcards");

var automatic = PatchCatalog.LoadAutomatic();
Ensure(automatic.Count == 3, "automatic catalog contains three upstream families");
Ensure(automatic.All(p => p.Architecture == "x64"), "automatic catalog uses x64");
foreach (var profile in automatic)
{
    var source = FakeBytes(profile.Groups.Single());
    string sha = SystemInfo.Sha256(source);
    var plan = PatchCatalog.Inspect(source, "fake.dll", "1.0", sha, true, [profile]);
    Ensure(plan.State == PatchState.Ready, "auto signature ready: " + profile.Label);
    Ensure(plan.Edits.Single().Offset == 40, "auto signature offset: " + profile.Label);
    Ensure(plan.PatchedBytes is not null && !source.SequenceEqual(plan.PatchedBytes),
        "replacement different: " + profile.Label);
    var patched = PatchCatalog.Inspect(plan.PatchedBytes!, "fake.dll", "1.0", "patched", true, [profile]);
    Ensure(patched.State == PatchState.AlreadyPatched, "already-patched recognition: " + profile.Label);
}

// Last-resort Revert with NO backup/journal can reverse ONLY fully fixed
// original bytes. Generic wildcard patterns lose information irreversibly.
foreach (var profile in automatic.Skip(1))
{
    var originalBytes = FakeBytes(profile.Groups.Single());
    var syntheticPatchedPlan = PatchCatalog.Inspect(originalBytes, "fake.dll",
        "1.0", SystemInfo.Sha256(originalBytes), true, [profile]);
    Ensure(syntheticPatchedPlan.PatchedBytes is not null, "source-free fixed profile prepares sample");
    Ensure(ExactCatalogRevert.TryReverseGroups(syntheticPatchedPlan.PatchedBytes!,
            profile.Groups, out var recoveredOriginal, out var reverseEdits) &&
           recoveredOriginal.SequenceEqual(originalBytes) && reverseEdits.Length == 1,
        "13/19 byte fully fixed pattern can be reversed without guessing original bytes");
    var changed = (byte[])syntheticPatchedPlan.PatchedBytes!.Clone();
    new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(changed, 90);
    var repeatedReplacement = (byte[])syntheticPatchedPlan.PatchedBytes!.Clone();
    profile.Groups[0].Replace.CopyTo(repeatedReplacement, 100);
    Ensure(!ExactCatalogRevert.TryReverseGroups(repeatedReplacement, profile.Groups,
            out _, out _), "duplicate replacement signature cannot be automatically reversed");
}
var genericSource = FakeBytes(automatic[0].Groups.Single());
var genericPatched = PatchCatalog.Inspect(genericSource, "fake.dll", "1.0",
    SystemInfo.Sha256(genericSource), true, [automatic[0]]);
Ensure(genericPatched.PatchedBytes is not null &&
       !ExactCatalogRevert.TryReverseGroups(genericPatched.PatchedBytes,
           automatic[0].Groups, out _, out _),
    "generic wildcard loses original bytes: no reverse without evidence");
Ensure(!ExactCatalogRevert.TryReverseGroups(new byte[256], automatic[1].Groups,
        out _, out _), "unknown file never gets a reverse candidate");

var old = PatchCatalog.Parse("# Windows 10 22H2\nx64, 11 22 33 44, AA BB CC DD\n");
Ensure(old.Count == 1 && old[0].Label.StartsWith("Windows 10"), "manual catalog labels");
var made = FakeBytes(new BytePattern("11 22 33 44", "AA BB CC DD"));
var ready = PatchCatalog.Inspect(made, "fake.dll", "1.0", SystemInfo.Sha256(made), true, old);
Ensure(ready.State == PatchState.Ready, "manual unique known signature ready");
Ensure(ready.PatchedBytes![40] == 0xAA, "preview changes expected byte");
Ensure(PatchCatalog.Inspect(ready.PatchedBytes!, "fake.dll", "1.0", "patched", true, old).State ==
    PatchState.AlreadyPatched, "manual already-patched recognition");
Ensure(PatchCatalog.Inspect(new byte[100], "fake.dll", "1.0", "test", true, old).State == PatchState.Unknown,
    "no match is unknown");
Ensure(PatchCatalog.Inspect(made, "fake.dll", "1.0", "test", false, old).State == PatchState.Unsupported,
    "unsupported target blocked");
new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(made, 80);
Ensure(PatchCatalog.Inspect(made, "fake.dll", "1.0", "test", true, old).State == PatchState.Ambiguous,
    "repeated pattern blocked");

var grouped = PatchCatalog.Parse("# Windows grouped\nx64, 11 22 33 44 | 55 66 77 88, AA BB CC DD | EE FF 00 01");
var groupedBytes = Enumerable.Repeat((byte)0xFA, 256).ToArray();
new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(groupedBytes, 16);
new byte[] { 0x55, 0x66, 0x77, 0x88 }.CopyTo(groupedBytes, 90);
var groupPreview = PatchCatalog.Inspect(groupedBytes, "fake.dll", "1.0", "test", true, grouped);
Ensure(groupPreview.State == PatchState.Ready && groupPreview.Edits.Count == 2,
    "multi-group patch stays atomic");
Ensure(PatchCatalog.Inspect(groupPreview.PatchedBytes!, "fake.dll", "1.0", "test", true, grouped).State ==
    PatchState.AlreadyPatched, "multi-group already patched");
new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }.CopyTo(groupedBytes, 16);
Ensure(PatchCatalog.Inspect(groupedBytes, "fake.dll", "1.0", "test", true, grouped).State == PatchState.Ambiguous,
    "partially modified multi-group blocked");
Expect<FormatException>(() => PatchCatalog.Parse("x64, 11 22 33 44, 44 55 66"),
    "reject groups with different lengths");
Expect<FormatException>(() => PatchCatalog.Parse("arm64, 11 22 33 44, 44 55 66 77"),
    "reject unsupported architecture");
Ensure(PatchCatalog.Manual("11 * 33 44 | 55 66 77 88", "AA BB CC DD | 90 90 90 90").Groups.Count == 2,
    "manual multi-group parsing");

var near = FakeBytes(automatic[1].Groups.Single());
near[40 + 12] ^= 1; // Change just the last fixed byte in the 24H2 family.
Ensure(PatchCatalog.Inspect(near, "fake.dll", "1.0", "test", true, automatic).State == PatchState.Unknown,
    "changed automatic signature no longer trusted");
var suggestions = NearMatchFinder.Find(near, automatic);
Ensure(suggestions.Any(s => s.Offset == 40 && s.DifferentByteIndexes.SequenceEqual([12])),
    "read-only similarity finds one differing byte");
Ensure(NearMatchFinder.Find(new byte[256], automatic).Count == 0,
    "no false near-match from all-zero data");

// A deliberately minimal in-memory AMD64 PE DLL, used only for header and range tests.
var pe = new byte[0x500];
pe[0] = (byte)'M'; pe[1] = (byte)'Z';
BinaryPrimitives.WriteInt32LittleEndian(pe.AsSpan(0x3C, 4), 0x80);
new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(pe, 0x80);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x84, 2), 0x8664);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x86, 2), 1);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x94, 2), 0xF0);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x96, 2), 0x2000);
BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(0x98, 2), 0x20B);
int section = 0x80 + 24 + 0xF0;
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 16, 4), 0x100);
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 20, 4), 0x200);
BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(section + 36, 4), 0x60000020);
Ensure(PeSafety.ReadAmd64DllSections(pe).Count == 1, "AMD64 DLL sections recognized");
PeSafety.RequireExecutableEdits(pe, [new PatchEdit(0x220, [1, 2, 3, 4], [5, 6, 7, 8])]);
assertions++;
Expect<InvalidDataException>(() => PeSafety.RequireExecutableEdits(pe,
    [new PatchEdit(0x100, [1, 2, 3, 4], [5, 6, 7, 8])]), "reject edit inside PE headers");
Expect<InvalidDataException>(() => PeSafety.RequireExecutableEdits(pe,
    [new PatchEdit(0x2FE, [1, 2, 3, 4], [5, 6, 7, 8])]), "reject edit crossing section boundary");
var notDll = (byte[])pe.Clone();
BinaryPrimitives.WriteUInt16LittleEndian(notDll.AsSpan(0x96, 2), 0);
Expect<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(notDll), "reject non-DLL PE");
Expect<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(new byte[200]), "reject non-PE file");

// End-to-end source-free Revert eligibility on a synthetic AMD64 DLL.
// No system DLL, TermService or Windows settings are changed.
foreach (var (profile, display, build) in new[]
{
    (automatic[1], "24H2", 26100),
    (automatic[2], "26H2", 26200)
})
{
    var source = (byte[])pe.Clone();
    var group = profile.Groups.Single();
    group.Search.Select(b => b!.Value).ToArray().CopyTo(source, 0x220);
    var patched = (byte[])source.Clone();
    group.Replace.CopyTo(patched, 0x220);
    var details = new WindowsDetails("Windows 11", display, build, 100,
        "Client", true, @"C:\Windows\System32\termsrv.dll",
        "10.0." + build + ".100");
    var fallback = ExactCatalogRevert.Inspect(details, patched);
    Ensure(fallback is not null &&
           fallback.Plan.RecoverySource == "ExactCatalog" &&
           fallback.OriginalBytes.SequenceEqual(source) &&
           fallback.Plan.InstalledSha256.Equals(SystemInfo.Sha256(patched),
               StringComparison.OrdinalIgnoreCase),
        "source-free 24H2/26H2 Revert works with exact reversible PE bytes");
    var wrongFamily = details with { DisplayVersion = "27H2" };
    Ensure(ExactCatalogRevert.Inspect(wrongFamily, patched) is null,
        "unknown Windows build must not reconstruct DLL without backup");
}
var unknownPe = (byte[])pe.Clone();
Ensure(ExactCatalogRevert.Inspect(
       new WindowsDetails("Windows 11", "26H2", 26200, 1, "Client",
           true, @"C:\Windows\System32\termsrv.dll", "10.0.26200.1"),
       unknownPe) is null,
    "unrecognized DLL without backup or journal cannot be reconstructed");

// Check native library platform gates without loading any native code.
Ensure(!NsudoDevilModeScope.IsBundled || OperatingSystem.IsWindows(),
    "embedded native NSudo package must be a Windows build resource");
var nativePe = (byte[])pe.Clone();
NsudoDevilModeScope.EnsureAmd64Dll(nativePe);
assertions++;
Expect<InvalidDataException>(() => NsudoDevilModeScope.EnsureAmd64Dll(new byte[100]),
    "native NSudo rejects a non-PE file");
Expect<InvalidDataException>(() => NsudoDevilModeScope.EnsureAmd64Dll(notDll),
    "native NSudo rejects a non-DLL file");
// Direct publishing is user-initiated and fully mocked in CI: no actual token,
// network access, issue creation, machine identity or protected DLL modification.
var eventId = Guid.NewGuid().ToString("D");
var reviewed = $"<!-- udx-report-id:{eventId} -->\n## Universal Diagnostics (operator-reviewed)\n" +
    "\n- Project: `sgennadi/TermsrvPatcherUnified`\n\n### Description (redacted)\nSafe test report";
var syntheticToken = "github_pat_" + new string('X', 42);
var issueJson = "{\"html_url\":\"https://github.com/sgennadi/TermsrvPatcherUnified/issues/42\"}";
var allowedHandler = new IssueStubHandler(HttpStatusCode.Created, issueJson);
using (var http = new HttpClient(allowedHandler))
using (var publisher = new GitHubIssuePublisher(http))
{
    var issue = publisher.PublishAsync(reviewed, eventId, syntheticToken).GetAwaiter().GetResult();
    Ensure(GitHubIssuePublisher.IsApprovedIssueUri(issue), "expected GitHub issue URL accepted");
    Ensure(allowedHandler.RequestCount == 1, "direct publisher sends once");
    Ensure(allowedHandler.LastMethod == HttpMethod.Post, "GitHub issue publishing uses POST");
    Ensure(allowedHandler.LastUrl == "https://api.github.com/repos/sgennadi/TermsrvPatcherUnified/issues",
        "issue publishing destination pinned");
    Ensure(allowedHandler.LastBearer == syntheticToken, "temporary token passed in request header only");
    Ensure(!allowedHandler.LastBody.Contains(syntheticToken, StringComparison.Ordinal) &&
        allowedHandler.LastBody.Contains(eventId, StringComparison.Ordinal),
        "GitHub request body excludes token and contains reviewed report ID");
    Expect<ArgumentException>(() => publisher.PublishAsync(reviewed, eventId, "bad token").GetAwaiter().GetResult(),
        "reject whitespace and invalid temporary token");
    Expect<ArgumentException>(() => publisher.PublishAsync("unreviewed", eventId, syntheticToken).GetAwaiter().GetResult(),
        "reject unreviewed diagnostic payload");
    Ensure(allowedHandler.RequestCount == 1, "invalid requests never reach GitHub");
}
foreach (var (code, response) in new[] {
    (HttpStatusCode.Redirect, issueJson),
    (HttpStatusCode.Forbidden, "{\"message\":\"Forbidden\"}")})
{
    using var http = new HttpClient(new IssueStubHandler(code, response));
    using var pub = new GitHubIssuePublisher(http);
    Expect<InvalidOperationException>(() => pub.PublishAsync(reviewed, eventId, syntheticToken).GetAwaiter().GetResult(),
        "reject non-201 GitHub response without forwarding credentials");
}
using (var http = new HttpClient(new IssueStubHandler(HttpStatusCode.Created,
    "{\"html_url\":\"https://example.com/other/issues/42\"}")))
using (var publisher = new GitHubIssuePublisher(http))
    Expect<InvalidDataException>(() => publisher.PublishAsync(reviewed, eventId, syntheticToken).GetAwaiter().GetResult(),
        "reject untrusted GitHub Issue URL");
Ensure(!GitHubIssuePublisher.IsApprovedIssueUri(new Uri("https://github.com/other/repo/issues/1")),
    "reject mismatched GitHub repository");
Ensure(!GitHubIssuePublisher.IsApprovedIssueUri(new Uri("https://github.com/sgennadi/TermsrvPatcherUnified/issues/1?view=all")),
    "reject GitHub Issue URLs containing query parameters");

// Anonymous shared transport: only typed metadata and confirmed server receipts.
var anonymousEvent = new
{
    @event = new {
        schema = "universal-diagnostics/v1",
        id = Guid.NewGuid().ToString("D"),
        timestamp_utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        project = "sgennadi/TermsrvPatcherUnified",
        component = "RdpSettings",
        error_type = "InvalidOperationException",
        code = "0x80131509",
        level = "error",
        version = UpdateIntegration.Version,
        platform = "Windows",
        architecture = "AMD64",
        fingerprint = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes("sgennadi/termsrvpatcherunified|rdpsettings|invalidoperationexception|0x80131509")))
    },
    summary = "PRIVATE SUMMARY MUST NEVER BE SENT",
    delivery = new { status = "pending", url = "" }
};
var anonymousPayload = UniversalDiagnosticsRelayClient.Prepare(JsonSerializer.Serialize(anonymousEvent));
Ensure(!anonymousPayload.Json.Contains("PRIVATE SUMMARY", StringComparison.Ordinal) &&
    !anonymousPayload.Json.Contains("delivery", StringComparison.Ordinal),
    "anonymous payload excludes summary and local queue delivery state");
var typedRecord = JsonNode.Parse(JsonSerializer.Serialize(anonymousEvent))
    ?? throw new InvalidOperationException("Synthetic anonymous payload missing.");
var typedEvent = (JsonObject)typedRecord["event"]!;
typedEvent["windows_release"] = "25H2";
typedEvent["windows_build"] = 26200;
typedEvent["windows_ubr"] = 1234;
typedEvent["dll_version"] = "10.0.26200.1234";
typedEvent["dll_sha256"] = new string('a', 64);
var typedPayload = UniversalDiagnosticsRelayClient.Prepare(typedRecord.ToJsonString());
Ensure(typedPayload.Json.Contains("\"dll_sha256\"", StringComparison.Ordinal) &&
       typedPayload.Json.Contains(new string('a', 64), StringComparison.Ordinal) &&
       typedPayload.Json.Contains("\"windows_build\": 26200", StringComparison.Ordinal) &&
       !typedPayload.Json.Contains("PRIVATE SUMMARY", StringComparison.Ordinal),
       "reviewed DLL SHA256, build and UBR survive typed anonymous preparation without summary");
typedEvent.Remove("dll_sha256");
Expect<InvalidDataException>(() => UniversalDiagnosticsRelayClient.Prepare(typedRecord.ToJsonString()),
    "incomplete Windows DLL evidence must not become an anonymous report");
typedEvent["dll_sha256"] = "not-a-hash";
Expect<InvalidDataException>(() => UniversalDiagnosticsRelayClient.Prepare(typedRecord.ToJsonString()),
    "untrusted DLL SHA256 never reaches HTTPS transport");
typedEvent["dll_sha256"] = new string('a', 64);
typedEvent["windows_build"] = "26200";
Expect<InvalidDataException>(() => UniversalDiagnosticsRelayClient.Prepare(typedRecord.ToJsonString()),
    "Windows build must be a number, not arbitrary text");
Ensure(new DiagnosticEnvironment("25H2", 26200, 1234, "10.0.26200.1234",
       new string('a', 64)).Valid &&
       !new DiagnosticEnvironment("25H2", 26200, 1234, "10.0.26200.1234",
       "invalidhash").Valid,
       "local diagnostic snapshot verifies release, DLL version and exact SHA256 shape");
Ensure(UniversalDiagnosticsRelayClient.IsApprovedEndpoint(
    new Uri("https://diagnostics.example.org/v1/diagnostics")),
    "HTTPS relay endpoint accepted");
Ensure(!UniversalDiagnosticsRelayClient.IsApprovedEndpoint(
    new Uri("http://diagnostics.example.org/v1/diagnostics")),
    "plaintext relay endpoint rejected");
var anonymousReceipt = JsonSerializer.Serialize(new {
    schema = "universal-diagnostics-relay/v1",
    id = anonymousPayload.EventId,
    project = anonymousPayload.Project,
    status = "submitted",
    issue_url = "https://github.com/sgennadi/TermsrvPatcherUnified/issues/42"
});
var anonymousHandler = new IssueStubHandler(HttpStatusCode.Created, anonymousReceipt);
using (var http = new HttpClient(anonymousHandler))
using (var sender = new UniversalDiagnosticsRelayClient(http))
{
    var result = sender.SendAsync(anonymousPayload,
        new Uri("https://diagnostics.example.org/v1/diagnostics")).GetAwaiter().GetResult();
    Ensure(result.AbsoluteUri.EndsWith("/issues/42", StringComparison.Ordinal),
        "anonymous relay receipt acknowledges correct GitHub Issue");
    Ensure(anonymousHandler.LastBearer.Length == 0 &&
        !anonymousHandler.LastBody.Contains("PRIVATE SUMMARY", StringComparison.Ordinal) &&
        anonymousHandler.LastBody.Contains(anonymousPayload.EventId, StringComparison.Ordinal),
        "anonymous send requires no client token and excludes sensitive free text");
}
using (var http = new HttpClient(new IssueStubHandler(HttpStatusCode.ServiceUnavailable, "{}")))
using (var sender = new UniversalDiagnosticsRelayClient(http))
    Expect<InvalidOperationException>(() => sender.SendAsync(anonymousPayload,
        new Uri("https://diagnostics.example.org/v1/diagnostics")).GetAwaiter().GetResult(),
        "unavailable relay never confirms delivery");
using (var http = new HttpClient(new IssueStubHandler(HttpStatusCode.Created,
    anonymousReceipt.Replace("/issues/42", "/issues/42?leak=1"))))
using (var sender = new UniversalDiagnosticsRelayClient(http))
    Expect<InvalidDataException>(() => sender.SendAsync(anonymousPayload,
        new Uri("https://diagnostics.example.org/v1/diagnostics")).GetAwaiter().GetResult(),
        "anonymous receipt rejects untrusted GitHub Issue URL");

// Recompute fingerprint mismatch and endpoint validation without network.
var invalidAnonymousRecord = JsonSerializer.Serialize(new {
    @event = new {
        schema = "universal-diagnostics/v1",
        id = Guid.NewGuid().ToString("D"),
        timestamp_utc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        project = DiagnosticsBridge.Project,
        component = "Application", error_type = "USER_REPORT", code = "MANUAL",
        level = "error", version = UpdateIntegration.Version,
        platform = "Windows", architecture = "AMD64",
        fingerprint = new string('0', 64)
    }
});
Expect<InvalidDataException>(
    () => UniversalDiagnosticsRelayClient.Prepare(invalidAnonymousRecord),
    "invalid fingerprint blocks an anonymous report before HTTPS");
Ensure(!UniversalDiagnosticsRelayClient.IsApprovedEndpoint(
        new Uri("https://diagnostics.example.org/v1/diagnostics?token=hidden")),
    "relay query strings and hidden credentials are rejected");
// Local delivery reconciliation: the canonical embedded diagnostics module is
// used as-is and never publishes to GitHub on its own.
var previousDirectory = Environment.GetEnvironmentVariable("UDX_STATE_DIR");
var scratch = Path.Combine(Path.GetTempPath(), "TermsrvPatcherUnified-Tests-" + Guid.NewGuid().ToString("N"));
try
{
    Environment.SetEnvironmentVariable("UDX_STATE_DIR", scratch);
    var receipt = DiagnosticsBridge.Capture(
        new DiagnosticsBridge.DiagnosticDraft("OfflineTest", "USER_REPORT", "TEST", "Review"),
        "Sanitized synthetic report");
    var record = File.ReadAllText(receipt.Path);
    Ensure(record.Contains("universal-diagnostics/v1", StringComparison.Ordinal),
        "local collector writes canonical v1 diagnostics");
    var markdown = DiagnosticsBridge.ReportMarkdown(record);
    Ensure(markdown.Contains(receipt.Id, StringComparison.Ordinal), "readable markdown reflects local report");
    var environment = new DiagnosticEnvironment("25H2", 26200, 1234,
        "10.0.26200.1234", new string('a', 64));
    var evidenceReceipt = DiagnosticsBridge.Capture(
        new DiagnosticsBridge.DiagnosticDraft("RdpSettings", "USER_REPORT", "TEST", "Review"),
        "Sanitized synthetic environment", environment);
    var evidenceRecord = File.ReadAllText(evidenceReceipt.Path);
    using var evidenceJson = JsonDocument.Parse(evidenceRecord);
    var evidenceEvent = evidenceJson.RootElement.GetProperty("event");
    Ensure(evidenceEvent.GetProperty("windows_build").GetInt32() == 26200 &&
           evidenceEvent.GetProperty("windows_ubr").GetInt32() == 1234 &&
           evidenceEvent.GetProperty("dll_sha256").GetString() == new string('a', 64),
           "canonical collector persists typed Windows build and SHA256 evidence");
    var evidencePreview = DiagnosticsBridge.ReportMarkdown(evidenceRecord);
    Ensure(evidencePreview.Contains("26200", StringComparison.Ordinal) &&
           evidencePreview.Contains(new string('a', 64), StringComparison.Ordinal),
           "the operator preview contains the exact typed metadata that can be shared");
    var preparedEvidence = UniversalDiagnosticsRelayClient.Prepare(evidenceRecord);
    Ensure(preparedEvidence.Json.Contains("\"dll_sha256\"", StringComparison.Ordinal) &&
           !preparedEvidence.Json.Contains("Sanitized synthetic environment", StringComparison.Ordinal),
           "anonymous payload copies valid typed evidence but excludes description");
    var issue = new Uri("https://github.com/sgennadi/TermsrvPatcherUnified/issues/42");
    DiagnosticsBridge.MarkSubmitted(receipt.Path, receipt.Id, issue);
    using var json = JsonDocument.Parse(File.ReadAllText(receipt.Path));
    var delivery = json.RootElement.GetProperty("delivery");
    Ensure(delivery.GetProperty("status").GetString() == "submitted" &&
        delivery.GetProperty("url").GetString() == issue.AbsoluteUri,
        "approved GitHub Issue URL acknowledged in local queue");
    Expect<InvalidOperationException>(() => DiagnosticsBridge.MarkSubmitted(receipt.Path, receipt.Id, issue),
        "repeated acknowledged submission blocked");
    Expect<UnauthorizedAccessException>(() => DiagnosticsBridge.MarkSubmitted(
        Path.Combine(scratch, "not-my-report.json"), receipt.Id, issue),
        "only project-owned queue reports can be acknowledged");
}
finally
{
    Environment.SetEnvironmentVariable("UDX_STATE_DIR", previousDirectory);
    if (Directory.Exists(scratch)) Directory.Delete(scratch, recursive: true);
}

Ensure(UpdateIntegration.Options(UniversalUpdater.UpdateChannel.Prerelease)
    .Assets.Single().AssetName == "TermsrvPatcherUnified-update-win-x64.zip",
    "Updater points to exact single-EXE GitHub asset");
Ensure(UpdateInstallBridge.Probe("0.1.0-preview.6") != 0,
    "Version-mismatched update probes are rejected");
Ensure(UpdateInstallBridge.Probe(UpdateIntegration.Version) is 0 or 5,
    "Update probe returns only explicit success or unavailable");
// Successful-fix v2 is opt-in: original/result SHA-256 and exact modified ranges.
var detailed = SuccessfulFixMetadata.FromSuccessfulApply(
    new WindowsDetails("Windows 11", "24H2", 26100, 1234, "Client",
        true, @"C:\Windows\System32\termsrv.dll", "10.0.26100.1234"), ready);
var successBody = detailed.AsComment();
Ensure(successBody.StartsWith("termsrv-success/v2\n", StringComparison.Ordinal),
    "compatibility report uses v2 marker");
Ensure(successBody.Contains("windows=Windows 11\n", StringComparison.Ordinal) &&
       successBody.Contains("build=26100\n", StringComparison.Ordinal) &&
       successBody.Contains("dll=1.0\n", StringComparison.Ordinal) &&
       successBody.Contains("app=" + UpdateIntegration.Version + "\n", StringComparison.Ordinal),
    "report contains expected Windows, DLL and application versions");
Ensure(successBody.Contains("original_sha256=" + ready.OriginalSha256, StringComparison.Ordinal) &&
       successBody.Contains("patched_sha256=" + SystemInfo.Sha256(ready.PatchedBytes!), StringComparison.Ordinal),
    "report contains original and modified SHA-256");
Ensure(successBody.Contains("edits=0x00000028:11223344>AABBCCDD", StringComparison.Ordinal),
    "report includes offset and before/after bytes");
Ensure(!successBody.Contains("C:\\", StringComparison.Ordinal) &&
       !successBody.Contains("hostname=", StringComparison.Ordinal) &&
       !successBody.Contains("username=", StringComparison.Ordinal),
    "report excludes hostnames, users and file paths");
var successHandler = new IssueStubHandler(HttpStatusCode.Created, "{}");
using (var client = new HttpClient(successHandler))
using (var sender = new SuccessfulFixPublisher(client))
{
    sender.PublishAsync(detailed, syntheticToken).GetAwaiter().GetResult();
    Ensure(successHandler.RequestCount == 1 &&
           successHandler.LastUrl ==
             "https://api.github.com/repos/sgennadi/TermsrvPatcherUnified/issues/1/comments",
        "report goes only to pinned public compatibility issue");
    Ensure(successHandler.LastBody.Contains("termsrv-success/v2", StringComparison.Ordinal) &&
           successHandler.LastBody.Contains("original_sha256=", StringComparison.Ordinal) &&
           !successHandler.LastBody.Contains(syntheticToken, StringComparison.Ordinal),
        "GitHub request includes hashes but excludes token");
    Expect<ArgumentException>(() => sender.PublishAsync(detailed, "bad token")
        .GetAwaiter().GetResult(), "reject invalid compatibility token");
}
using (var client = new HttpClient(new IssueStubHandler(HttpStatusCode.Forbidden, "{}")))
using (var sender = new SuccessfulFixPublisher(client))
    Expect<InvalidOperationException>(() => sender.PublishAsync(detailed, syntheticToken)
        .GetAwaiter().GetResult(), "failed GitHub authorization does not imply success");
Expect<InvalidDataException>(() => (detailed with { OriginalSha256 = "00" }).AsComment(),
    "reject invalid original SHA-256");
Expect<InvalidDataException>(() => (detailed with { PatchedSha256 = detailed.OriginalSha256 }).AsComment(),
    "reject unchanged file checksum");
Expect<InvalidDataException>(() => (detailed with {
    Changes = [new ChangedBytes(40, "11223344", "11223344")] }).AsComment(),
    "reject unchanged edited bytes");
Expect<InvalidDataException>(() => (detailed with {
    Changes = [new ChangedBytes(40, "11223344", "AABBCCDD"),
               new ChangedBytes(42, "1122", "3344")] }).AsComment(),
    "reject overlapping edit offsets");
Expect<InvalidDataException>(() => (detailed with { Mode = "manual\nhost=PRIVATE" }).AsComment(),
    "reject unapproved compatibility metadata");
Ensure(!UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.ReadAndExecute),
    "standard Program Files read/execute ACE cannot block updates");
Ensure(!UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.Read),
    "read access alone is not treated as write access");
Ensure(UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.WriteData),
    "file-creation rights are considered mutating");
Ensure(UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.CreateDirectories),
    "directory-creation rights are considered mutating");
Ensure(UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.Delete),
    "delete rights are considered mutating");
Ensure(UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.ChangePermissions),
    "permission-change rights are considered mutating");
Ensure(UpdateInstallBridge.HasMutatingRights(
        System.Security.AccessControl.FileSystemRights.Modify),
    "modify rights remain restricted");
Ensure(UpdateTransactionSyntheticTests.Run() == 2,
    "real File.Replace synthetic transaction passed success and rollback");
Console.WriteLine($"PASS: {assertions} TermsrvPatcher Unified read-only and preflight assertions.");

internal sealed class IssueStubHandler : HttpMessageHandler
{
    private readonly HttpStatusCode code;
    private readonly string responseBody;
    public int RequestCount { get; private set; }
    public HttpMethod? LastMethod { get; private set; }
    public string LastUrl { get; private set; } = "";
    public string LastBearer { get; private set; } = "";
    public string LastBody { get; private set; } = "";

    public IssueStubHandler(HttpStatusCode code, string responseBody)
    {
        this.code = code;
        this.responseBody = responseBody;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        RequestCount++;
        LastMethod = request.Method;
        LastUrl = request.RequestUri?.AbsoluteUri ?? "";
        LastBearer = request.Headers.Authorization?.Parameter ?? "";
        LastBody = request.Content?.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult() ?? "";
        return Task.FromResult(new HttpResponseMessage(code)
        {
            RequestMessage = request,
            Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
        });
    }
}
