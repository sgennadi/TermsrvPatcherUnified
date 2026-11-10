using TermsrvPatcherUnified.Core;

internal static class DllCompatibilityTests
{
    private static int checks;
    private static void Verify(bool value, string description)
    {
        checks++;
        if (!value) throw new Exception("DLL compatibility QA: " + description);
    }

    internal static int Run()
    {
        checks = 0;
        string sha = new string('a', 64);
        string beforeSha = new string('b', 64);
        var current = new DllHealthSnapshot(DllHealthSnapshot.SchemaId,
            "10.0.26100.9549", sha, 1536, DateTimeOffset.UtcNow);
        var firstSeen = current with { ObservedUtc = DateTimeOffset.UtcNow.AddHours(-1) };
        var host = new WindowsDetails("Windows 11", "26H2", 26300, 9711,
            "Client", true, @"C:\Users\PrivateUser\termsrv.dll", current.DllVersion);
        const string obsHeader =
            "issue_number,event_id,observed_utc,received_utc,windows_release,windows_build,windows_ubr,dll_version,dll_sha256,app_version,component,error_type,error_code,severity,architecture,verification";
        const string successHeader =
            "windows,release,build,ubr,file_name,dll_version,app_version,mode,original_sha256,patched_sha256,edits,first_seen_utc,last_seen_utc,report_count";
        string observations = obsHeader + "\n" +
            string.Join(",", "32", "synthetic-uuid", "2026-11-10T14:56:49Z",
                "2026-11-10T14:59:09Z", "26H2", "26300", "9711",
                current.DllVersion, sha, "1.0.4", "Application", "USER_REPORT",
                "MANUAL", "error", "AMD64", "unverified") + "\n";
        string successes = successHeader + "\n" +
            string.Join(",", "Windows 11", "26H2", "26300", "9711", "termsrv.dll",
                current.DllVersion, "1.0.4", "automatic", beforeSha, sha,
                "0x00000220:11223344>AABBCCDD", "2026-11-10T12:00:00Z",
                "2026-11-10T13:00:00Z", "2") + "\n";

        var index = DllCompatibilityIndex.Analyze(current, host, observations, successes, firstSeen);
        Verify(index.EvidenceComplete, "synthetic CSV rows parse as metadata");
        Verify(index.MatchingObservations == 1, "exact DLL version and SHA-256 matched");
        Verify(index.MatchingReportedFixes == 2, "aggregated user report count parsed");
        Verify(index.Rows.Count >= 6, "distinct evidence/trust boundary rows");
        Verify(index.Rows.Single(r => r.Check == "Anonymous diagnostic observations")
            .Status == "Reported (unverified)", "diagnostic source cannot claim verification");
        Verify(index.Rows.Single(r => r.Check == "Self-reported successful fixes")
            .Status == "Reported (unverified)", "reported success cannot claim verification");
        Verify(index.Rows.Single(r => r.Check == "Authentic Microsoft original")
            .Status == "Not verified", "same hash never certifies Microsoft original");
        Verify(index.Rows.Single(r => r.Check == "Automatic Apply eligibility")
            .Status == "Separate check", "index cannot authorize Apply");
        Verify(!index.AsText().Contains("PrivateUser", StringComparison.Ordinal) &&
               !index.AsText().Contains(@"C:\Users", StringComparison.Ordinal),
            "export omits synthetic local path and username");
        Verify(index.AsText().Contains("NEVER authorizes Apply", StringComparison.Ordinal),
            "safe text warns that compatibility index cannot modify DLL");
        var unrelated = current with { Sha256 = new string('c', 64) };
        var unrelatedReport = DllCompatibilityIndex.Analyze(unrelated, host,
            observations, successes);
        Verify(unrelatedReport.MatchingObservations == 0 &&
               unrelatedReport.MatchingReportedFixes == 0,
            "same version without SHA match does not become compatible");
        var otherVersion = current with { DllVersion = "10.0.26100.9999" };
        Verify(DllCompatibilityIndex.Analyze(otherVersion, host, observations, successes)
            .MatchingObservations == 0, "different file version is not exact evidence");
        var invalidObservations = DllCompatibilityIndex.Analyze(current, host,
            obsHeader + "\nunsafe,data\n", successes);
        Verify(!invalidObservations.EvidenceComplete &&
               invalidObservations.Rows.Single(x => x.Check == "Anonymous diagnostic observations")
                   .Status == "Unavailable",
            "malformed CSV must become unavailable, not a false no-match");
        var invalidSuccess = DllCompatibilityIndex.Analyze(current, host,
            observations, successes.Replace(",2\n", ",-2\n", StringComparison.Ordinal));
        Verify(!invalidSuccess.EvidenceComplete &&
               invalidSuccess.MatchingReportedFixes == 0,
            "negative count rejects the whole successful-fix source");
        var noRecords = DllCompatibilityIndex.Analyze(current, host,
            obsHeader + "\n", successHeader + "\n");
        Verify(noRecords.EvidenceComplete &&
               noRecords.MatchingObservations == 0 &&
               noRecords.MatchingReportedFixes == 0,
            "valid empty catalog is distinct from invalid catalog");
        var missing = DllCompatibilityIndex.Analyze(current, host, null, null);
        Verify(!missing.EvidenceComplete &&
               missing.Rows.Any(r => r.Status == "Unavailable"),
            "missing embedded resource is UNKNOWN, not safe/verified");
        Verify(index.Rows.Single(x => x.Check == "First seen (local)")
            .Status == "Unverified", "first-seen metadata never becomes an original baseline");

        Console.WriteLine("PASS: " + checks + " offline DLL compatibility index checks. " +
            "No system DLL write, network call, license claim or automatic patch authorization.");
        return checks;
    }
}
