using System.IO;
using TermsrvPatcherUnified.Core;

internal static class RdpPolicyHistoryTests
{
    private static int count;
    private static void Verify(bool ok, string reason)
    {
        count++;
        if (!ok) throw new InvalidOperationException("RDP policy/history QA failed: " + reason);
    }

    internal static int Run()
    {
        var conflict = RdpPolicyDiagnostics.Evaluate("NLA", 0, 1, 0, 1);
        Verify(conflict.Assessment == "Policy differs", "different local and policy values reported");
        Verify(conflict.Explanation.Contains("override"), "conflicts explain possible precedence");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", 1, 1, 0, 1).Assessment ==
            "Policy configured", "equal settings still display policy presence");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", 1, null, 0, 1).Assessment ==
            "Local setting", "missing policy is not a conflict");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", null, null, 0, 1).Assessment ==
            "Unavailable", "missing values do not imply safe defaults");
        Verify(RdpPolicyDiagnostics.Evaluate("Port", 70000, null, 1, 65535).Assessment ==
            "Invalid value", "out-of-range values are rejected");
        Verify(RdpPolicyDiagnostics.Evaluate("Port", 3389, null, 1, 65535).Assessment ==
            "Local setting", "valid TCP port accepted");
        Verify(RdpPolicyDiagnostics.Evaluate("Security", 0, 2, 0, 2).Assessment ==
            "Policy differs", "security-layer conflicts detected");

        var root = Path.Combine(Path.GetTempPath(), "Termsrv-History-QA-" + Guid.NewGuid().ToString("N"));
        var file = Path.Combine(root, "events.jsonl");
        try
        {
            Verify(OperationHistory.ReadRecent(50, file).Entries.Count == 0 && !Directory.Exists(root),
                "viewing missing history does not create directories");
            Verify(!OperationHistory.TryRecord("Unknown", "Success", file: file),
                "unknown event categories refused");
            Verify(OperationHistory.TryRecord("Apply", "Success", "10.0.26100.1000",
                new string('a', 64), new string('b', 64), file: file),
                "bounded metadata appended to temporary history");
            Verify(OperationHistory.TryRecord("Restore", "Failure",
                failureType: "IOException", file: file), "failure type stored without message");
            Verify(OperationHistory.TryRecord("RdpSettings", "Success", file: file),
                "RDP setting event appended");
            var saved = OperationHistory.ReadRecent(2, file);
            Verify(saved.Entries.Count == 2 && saved.Entries[0].Operation == "RdpSettings" &&
                saved.Entries[1].Operation == "Restore",
                "latest entries returned in reverse chronological order");
            Verify(saved.Entries.All(e => e.IsValid()), "read validates schema and fields");
            Verify(!File.ReadAllText(file).Contains(root, StringComparison.OrdinalIgnoreCase) &&
                !File.ReadAllText(file).Contains("username", StringComparison.OrdinalIgnoreCase),
                "history contains no paths or account identities");
            File.AppendAllText(file, "{malformed" + Environment.NewLine);
            var corrupted = OperationHistory.ReadRecent(4, file);
            Verify(corrupted.InvalidEntries == 1 && corrupted.Entries.Count == 3,
                "malformed JSON ignored without losing verified entries");
            var validLine = File.ReadLines(file).First();
            var nullVersionLine = validLine.Replace(
                "\"AppVersion\":\"" + UpdateIntegration.Version + "\"",
                "\"AppVersion\":null", StringComparison.Ordinal);
            Verify(nullVersionLine != validLine, "test fixture contains an application version");
            File.AppendAllText(file, nullVersionLine + Environment.NewLine);
            var invalidFields = OperationHistory.ReadRecent(5, file);
            Verify(invalidFields.InvalidEntries == 2 && invalidFields.Entries.Count == 3,
                "JSON with null required fields is rejected without crashing the history view");
            Verify(!OperationHistory.TryRecord("Apply", "Unknown", file: file),
                "invalid outcome refused");
            Verify(OperationHistory.IsSha(new string('0', 64)) &&
                !OperationHistory.IsSha(new string('g', 64)), "SHA validation is exact");
            Verify(OperationHistory.IsDllVersion("10.0.26100.1000") &&
                !OperationHistory.IsDllVersion("../../user"), "DLL version sanitized");
            if (OperatingSystem.IsWindows())
            {
                var report = RdpPolicyDiagnostics.ReadLocal();
                Verify(report.Values.Count >= 6 && report.AsText().Contains("READ ONLY"),
                    "Windows registry/service read-only diagnostic report");
                Verify(!report.AsText().Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase),
                    "diagnostics never include local account name");
            }
            Console.WriteLine("PASS: " + count +
                " RDP policy and local operation history tests; no registry/service/DLL writes.");
            return count;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
