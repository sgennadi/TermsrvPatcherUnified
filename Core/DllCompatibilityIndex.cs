using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

internal sealed record DllCompatibilityRow(
    string Check, string Status, string Evidence, string NextStep);

internal sealed record DllCompatibilityReport(
    DateTimeOffset CheckedUtc, IReadOnlyList<DllCompatibilityRow> Rows,
    int MatchingObservations, int MatchingReportedFixes, bool EvidenceComplete)
{
    internal string Summary => EvidenceComplete
        ? "Exact DLL SHA-256: " + MatchingObservations +
          " anonymous observation(s), " + MatchingReportedFixes +
          " self-reported fix(es). All are UNVERIFIED; no Windows compatibility or licensing claim."
        : "Some bundled compatibility records could not be validated. Missing evidence is UNKNOWN, not a mismatch.";

    internal string AsText()
    {
        var sb = new StringBuilder()
            .AppendLine("DLL compatibility evidence - READ ONLY")
            .AppendLine("Checked UTC: " + CheckedUtc.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))
            .AppendLine(Summary)
            .AppendLine("No network request, report submission, DLL patch, service operation or policy change occurred.");
        foreach (var row in Rows)
        {
            sb.AppendLine().AppendLine("[" + row.Status + "] " + row.Check)
                .AppendLine("Evidence: " + row.Evidence)
                .AppendLine("Next: " + row.NextStep);
        }
        sb.AppendLine().AppendLine(
            "This index NEVER authorizes Apply, Revert, a patch signature, or Remote Desktop licensing.");
        return sb.ToString();
    }
}

/// <summary>
/// Read-only, bounded metadata index. Bundled CSV records are user-submitted evidence,
/// never an original-Microsoft-file baseline or an Apply trust decision.
/// </summary>
internal static class DllCompatibilityIndex
{
    private const string ObservationResource = "TermsrvPatcherUnified.Data.DiagnosticObservations.csv";
    private const string SuccessfulResource = "TermsrvPatcherUnified.Data.SuccessfulFixes.csv";
    private const string ObservationsHeader =
        "issue_number,event_id,observed_utc,received_utc,windows_release,windows_build,windows_ubr,dll_version,dll_sha256,app_version,component,error_type,error_code,severity,architecture,verification";
    private const string SuccessfulHeader =
        "windows,release,build,ubr,file_name,dll_version,app_version,mode,original_sha256,patched_sha256,edits,first_seen_utc,last_seen_utc,report_count";
    private static readonly Regex Sha = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Version = new(
        @"\A[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}\z",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SafeToken = new(
        @"\A[A-Za-z0-9._-]{1,90}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    internal static DllCompatibilityReport ReadLocal(DllHealthReport health)
    {
        ArgumentNullException.ThrowIfNull(health);
        // Do not download a catalog or contact a user-provided endpoint.
        var host = SystemInfo.Read();
        PatchPlan? signature = null;
        try
        {
            using var engine = new TermsrvEngine(null);
            signature = engine.Inspect(); // Read-only byte comparison; no Apply.
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or
                                   InvalidOperationException or UnauthorizedAccessException or
                                   System.ComponentModel.Win32Exception or ArgumentException)
        {
            // Failure is Unknown, not a verified Microsoft original.
        }
        return Analyze(health.Current, host, ReadEmbedded(ObservationResource),
            ReadEmbedded(SuccessfulResource), health.FirstSeen, health.Baseline, signature);
    }

    internal static DllCompatibilityReport Analyze(
        DllHealthSnapshot current, WindowsDetails host,
        string? observationsCsv, string? successfulCsv,
        DllHealthSnapshot? firstSeen = null, DllHealthSnapshot? manualBaseline = null,
        PatchPlan? signature = null)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(host);
        current.Validate();
        firstSeen?.Validate();
        manualBaseline?.Validate();

        var obs = Parse(observationsCsv, ObservationsHeader, 16, ObservationValid);
        var successes = Parse(successfulCsv, SuccessfulHeader, 14, SuccessValid);
        bool valid = obs.Valid && successes.Valid;
        bool consistent = string.Equals(current.DllVersion, host.DllVersion, StringComparison.OrdinalIgnoreCase);
        var observations = obs.Rows.Where(x =>
            x[8] == current.Sha256 && x[7] == current.DllVersion).ToArray();
        var sameEnvironment = observations.Count(x => x[4] == host.DisplayVersion &&
            int.TryParse(x[5], NumberStyles.None, CultureInfo.InvariantCulture, out int build) &&
            build == host.Build &&
            int.TryParse(x[6], NumberStyles.None, CultureInfo.InvariantCulture, out int ubr) &&
            ubr == host.Ubr);
        long reported = 0;
        int sourceReports = 0, resultReports = 0;
        foreach (var x in successes.Rows)
        {
            if (x[5] != current.DllVersion || (x[8] != current.Sha256 && x[9] != current.Sha256))
                continue;
            int count = int.Parse(x[13], CultureInfo.InvariantCulture);
            reported = Math.Min(1_000_000, reported + count);
            if (x[8] == current.Sha256) sourceReports++;
            if (x[9] == current.Sha256) resultReports++;
        }

        string reference = firstSeen is null ? "No first-seen snapshot available." :
            firstSeen.Sha256 == current.Sha256 && firstSeen.DllVersion == current.DllVersion
                ? "Same SHA-256 and version as the first locally observed file."
                : "Current SHA-256/version differs from the first locally observed file.";
        string manual = manualBaseline is null ? "No operator baseline saved." :
            manualBaseline.Sha256 == current.Sha256 && manualBaseline.DllVersion == current.DllVersion
                ? "Matches an operator-recorded reference; its origin is not authenticated."
                : "Differs from an operator-recorded reference; cause not determined.";

        // Registry and PE-version labels are not authenticated. Avoid copying
        // arbitrary local paths, user labels or machine names into evidence.
        string displayOs = host.Name is "Windows 10" or "Windows 11" or "Windows Server"
            ? host.Name : "(unavailable)";
        string displayRelease = SafeToken.IsMatch(host.DisplayVersion)
            ? host.DisplayVersion : "(unavailable)";
        string displayDllVersion = Version.IsMatch(current.DllVersion)
            ? current.DllVersion : "(unavailable)";

        bool sameSnapshot = signature is not null &&
            signature.OriginalSha256.Equals(current.Sha256, StringComparison.OrdinalIgnoreCase) &&
            signature.FileVersion.Equals(current.DllVersion, StringComparison.OrdinalIgnoreCase);
        string signatureStatus = signature is null ? "Unavailable" :
            !sameSnapshot ? "Stale snapshot" : signature.State switch
            {
                PatchState.Ready => "Exact original-pattern match",
                PatchState.AlreadyPatched => "Exact replacement-pattern match",
                PatchState.Ambiguous => "Ambiguous",
                PatchState.Unsupported => "Not eligible",
                _ => "No exact match"
            };
        string signatureEvidence = signature is null
            ? "Local automatic signature inspection unavailable."
            : !sameSnapshot
                ? "DLL SHA-256 or version changed between independent inspections."
                : "Embedded byte-pattern state: " + signature.State +
                  ". Matching bytes do not establish original Microsoft provenance, " +
                  "licensing or remote connectivity, and cannot authorize Apply.";

        var rows = new List<DllCompatibilityRow>
        {
            new("Installed DLL snapshot", consistent ? "Observed (local)" : "Review",
                displayOs + " " + displayRelease + ", build " + host.Build + "." +
                host.Ubr + "; DLL " + displayDllVersion + "; SHA-256 " + current.Sha256 + ". " +
                (consistent ? "Version readings agree." : "Windows/DLL readings changed during inspection."),
                "Re-run Check DLL health if Windows Update or a file operation occurred."),
            new("First seen (local)", firstSeen is null ? "Unavailable" : "Unverified",
                reference, "First seen is not a Microsoft original baseline."),
            new("Operator baseline", manualBaseline is null ? "Not recorded" : "Unverified",
                manual, "Only an independently authenticated original can establish file provenance."),
            new("Embedded signature", signatureStatus, signatureEvidence,
                "Protected Apply eligibility and its independent revalidation are unchanged."),
            new("Anonymous diagnostic observations",
                !obs.Valid ? "Unavailable" : observations.Length > 0 ? "Reported (unverified)" : "No exact match",
                !obs.Valid ? "Bundled observations could not be read or validated." :
                    observations.Length + " report(s) have this exact DLL version and SHA-256; " +
                    sameEnvironment + " also match this Windows release/build/UBR.",
                "Diagnostic receipt is not proof of RDP functionality or a successful fix."),
            new("Self-reported successful fixes",
                !successes.Valid ? "Unavailable" : reported > 0 ? "Reported (unverified)" : "No exact match",
                !successes.Valid ? "Bundled successful-fix metadata could not be read or validated." :
                    reported + " report(s) with exact DLL version and SHA-256; " +
                    sourceReports + " aggregate row(s) list it as before-state, " +
                    resultReports + " as after-state.",
                "Self-reports cannot certify an original file or grant permission to patch."),
            new("Authentic Microsoft original", "Not verified",
                "This index does not validate Microsoft provenance, catalog signatures or component-store identity.",
                "Use independently trusted Windows servicing and signature evidence for recovery."),
            new("Automatic Apply eligibility", "Separate check",
                "The compatibility index is informational and never participates in patch selection.",
                "Only the existing protected, explicit preview and independent safety checks may evaluate Apply.")
        };
        return new DllCompatibilityReport(DateTimeOffset.UtcNow, rows, observations.Length,
            (int)reported, valid);
    }

    private static string? ReadEmbedded(string name)
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
            if (stream is null || stream.Length > 1_000_000) return null;
            using var reader = new StreamReader(stream, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true);
            return reader.ReadToEnd();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private static (bool Valid, List<string[]> Rows) Parse(
        string? text, string header, int columns, Func<string[], bool> validRow)
    {
        if (text is null || text.Length > 1_000_000 || text.Contains('\0'))
            return (false, []);
        var lines = text.TrimEnd('\r', '\n').Split('\n');
        if (lines.Length is < 1 or > 20_001 ||
            lines[0].TrimEnd('\r').TrimStart('\uFEFF') != header)
            return (false, []);
        var rows = new List<string[]>(Math.Min(lines.Length - 1, 512));
        foreach (var raw in lines.Skip(1))
        {
            string line = raw.TrimEnd('\r');
            if (line.Length is < 1 or > 4096 || line.Any(char.IsControl))
                return (false, []);
            var cells = line.Split(',');
            if (cells.Length != columns || cells.Any(c => c.Length > 512) || !validRow(cells))
                return (false, []);
            rows.Add(cells);
        }
        return (true, rows);
    }

    private static bool ObservationValid(string[] row)
        => int.TryParse(row[0], NumberStyles.None, CultureInfo.InvariantCulture, out int id) &&
           id > 0 && SafeToken.IsMatch(row[4]) &&
           NonNegative(row[5]) && NonNegative(row[6]) &&
           Version.IsMatch(row[7]) && Sha.IsMatch(row[8]) &&
           SafeToken.IsMatch(row[9]) && SafeToken.IsMatch(row[14]) &&
           SafeToken.IsMatch(row[15]) &&
           DateTimeOffset.TryParse(row[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _) &&
           DateTimeOffset.TryParse(row[3], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _);

    private static bool SuccessValid(string[] row)
        => row[0] is "Windows 10" or "Windows 11" &&
           SafeToken.IsMatch(row[1]) && NonNegative(row[2]) && NonNegative(row[3]) &&
           row[4] == "termsrv.dll" && Version.IsMatch(row[5]) &&
           SafeToken.IsMatch(row[6]) && row[7] is "manual" or "automatic" &&
           Sha.IsMatch(row[8]) && Sha.IsMatch(row[9]) && row[8] != row[9] &&
           row[10].Length is > 0 and <= 512 &&
           DateTimeOffset.TryParse(row[11], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _) &&
           DateTimeOffset.TryParse(row[12], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _) &&
           int.TryParse(row[13], NumberStyles.None, CultureInfo.InvariantCulture, out int count) &&
           count is >= 1 and <= 1_000_000;

    private static bool NonNegative(string value)
        => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n) &&
           n is >= 0 and <= 999_999;
}
