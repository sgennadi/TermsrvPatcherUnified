using System.Text;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Exact evidence from one verified byte snapshot. Unlike a patch preview,
/// this snapshot has no capability to authorize replacement or service control.
/// </summary>
internal sealed record VerifiedSignatureSnapshot(
    string Sha256, byte[] Bytes, SignatureInspection Inspection)
{
    internal static VerifiedSignatureSnapshot Capture(byte[] bytes, PatchPlan plan,
        IReadOnlyList<PatchProfile> profiles, string architecture = "x64")
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(profiles);
        if (bytes.Length is < 1 or > 64 * 1024 * 1024)
            throw new InvalidDataException("The inspected DLL is outside the 64 MB evidence size limit.");
        string actual = SystemInfo.Sha256(bytes);
        if (!actual.Equals(plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "DLL content changed between patch preview and signature inspection. " +
                "Check DLL again; mismatched evidence is refused.");
        // Copy the data to prevent later modification of the evidence by callers.
        return new(actual, (byte[])bytes.Clone(),
            SignatureInspector.Analyze(bytes, profiles, architecture));
    }

    internal void RequireCurrentFile(string path)
    {
        if (!SystemInfo.Sha256(File.ReadAllBytes(path)).Equals(Sha256,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Installed DLL changed since signature inspection. Check DLL again.");
    }
}

internal static class SignatureEvidenceExport
{
    private static readonly Regex HashPattern = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex UnsafeMetadata = new(
        @"[\\\r\n\t<>@]|[A-Za-z]:[/\\]|(?:https?://)|(?:\\\\)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex AllowedPatternText = new(
        @"\A[0-9A-F*? ,x.]+\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    internal static string Build(WindowsDetails host, PatchPlan plan,
        VerifiedSignatureSnapshot snapshot, ScanReport? fallback = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!HashPattern.IsMatch(snapshot.Sha256) ||
            !SystemInfo.Sha256(snapshot.Bytes).Equals(snapshot.Sha256, StringComparison.Ordinal) ||
            !snapshot.Sha256.Equals(plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Signature evidence is not bound to the verified DLL SHA-256.");
        if (fallback is not null && !fallback.Sha256.Equals(
                snapshot.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Fallback scan is from a different DLL state; cannot mix report evidence.");
        if (snapshot.Inspection.Rows.Count > 256)
            throw new InvalidDataException("Too many signature groups for an evidence report.");

        var b = new StringBuilder();
        b.AppendLine("termsrv-signature-evidence/v1");
        b.AppendLine("Read-only operator export. No network submission occurred.");
        b.AppendLine("This report is evidence only and NEVER authorizes a DLL modification.");
        b.AppendLine("File: termsrv.dll (basename only)");
        b.AppendLine("Windows: " + Safe(host.Name, 48) + " " + Safe(host.DisplayVersion, 32));
        b.AppendLine("Windows build: " + host.Build + "." + host.Ubr);
        b.AppendLine("Architecture: " + (host.Is64Bit ? "x64" : "x86"));
        b.AppendLine("DLL version: " + Safe(plan.FileVersion, 100));
        b.AppendLine("DLL SHA-256: " + snapshot.Sha256);
        b.AppendLine("Automatic result: " + plan.State);
        if (plan.State is PatchState.Ready or PatchState.AlreadyPatched &&
            plan.ProfileId.Length > 0)
            b.AppendLine("Selected automatic profile (not execution evidence): " +
                Safe(plan.ProfileId, 130));
        b.AppendLine("Exact groups inspected: " + snapshot.Inspection.Rows.Count);
        b.AppendLine("Complete profile matches: " + snapshot.Inspection.CompleteProfileCount);
        b.AppendLine("Distinct candidate target sets: " + snapshot.Inspection.DistinctCandidateTargetCount);
        b.AppendLine("Within-profile conflicts: " + snapshot.Inspection.ConflictingProfileCount);
        if (snapshot.Inspection.DistinctCandidateTargetCount > 1)
            b.AppendLine("Ambiguity: MULTIPLE DISTINCT complete profile matches; OS-aware " +
                "priority is required to select one, while individual hits remain read-only evidence.");
        else if (snapshot.Inspection.ConflictingProfileCount > 0)
            b.AppendLine("Ambiguity: WITHIN-PROFILE repeated, mixed or conflicting bytes.");
        else
            b.AppendLine("Ambiguity: no distinct cross-profile conflict in the exact evidence.");
        // Never serialize the raw display summary: catalog labels are untrusted
        // and could contain local paths or other personal text.
        b.AppendLine("Profile-level inspection (labels redacted if unsafe):");
        foreach (var profile in snapshot.Inspection.Profiles.Take(256))
            b.AppendLine("  " + Safe(profile.Profile, 130) + " / " +
                Safe(profile.Classification, 115) + " / offsets " +
                Safe(profile.Offsets, 512) + " / fixed bytes " +
                profile.FixedBytes + " / groups " + profile.Groups);
        for (int index = 0; index < snapshot.Inspection.Rows.Count; index++)
        {
            var row = snapshot.Inspection.Rows[index];
            b.AppendLine();
            b.AppendLine("Group " + (index + 1) + ": " + Safe(row.Profile, 130) +
                " / #" + row.Group);
            b.AppendLine("  Finding: " + Safe(row.State, 90));
            b.AppendLine("  Find mask: " + SafePattern(row.FindHex));
            b.AppendLine("  Replace signature: " + SafePattern(row.ReplaceHex));
            b.AppendLine("  Aligned byte comparison (wildcards shown as ??):");
            b.AppendLine("    Find:    " + SafePattern(row.AlignedFindHex));
            b.AppendLine("    Replace: " + SafePattern(row.ReplaceHex));
            b.AppendLine("    Lengths: " + row.FindByteCount + "/" + row.ReplaceByteCount +
                " byte(s), " + row.FixedByteCount + " fixed, " +
                row.WildcardByteCount + " wildcard(s)");
            b.AppendLine("  Find hits: " + Safe(row.FindHits, 24) +
                         " at " + Safe(row.FindOffsets, 140));
            b.AppendLine("  Replace hits: " + Safe(row.ReplaceHits, 24) +
                         " at " + Safe(row.ReplaceOffsets, 140));
        }
        if (fallback is not null)
        {
            b.AppendLine();
            b.AppendLine("Read-only structural markers: " + fallback.Hits.Count);
            b.AppendLine("Near-match candidates: " + fallback.Similar.Count +
                " (NOT verified patches)");
            foreach (var match in fallback.Similar.Take(20))
                b.AppendLine("  0x" + match.Offset.ToString("X8") + " " +
                    Safe(match.Profile, 130) + " group " + match.GroupNumber +
                    ": " + match.MatchedBytes + "/" + match.FixedBytes +
                    " fixed bytes; mismatch byte indexes [" +
                    string.Join(", ", match.DifferentByteIndexes.Take(48)) + "]");
        }
        b.AppendLine();
        b.AppendLine("No absolute file paths, usernames, hostnames, IPs, full DLL contents or tokens are included.");
        b.AppendLine("Review the text yourself before sharing. GitHub Issue posting still requires sign-in.");
        return b.ToString();
    }

    private static string SafePattern(string value)
        => value is { Length: > 0 and <= 512 } && AllowedPatternText.IsMatch(value)
            ? value : "(unavailable)";

    private static string Safe(string? value, int max)
        => value is { Length: > 0 } && value.Length <= max &&
           !UnsafeMetadata.IsMatch(value) && value.All(c => c is >= ' ' and <= '~')
            ? value : "(unavailable)";

    internal static void SaveNew(string report, string destination)
    {
        const string schema = "termsrv-signature-evidence/v1";
        // StringBuilder.AppendLine uses the operating system's newline. Accept
        // CRLF on Windows and LF elsewhere, never a prefix of another schema.
        if (string.IsNullOrWhiteSpace(report) || report.Length > 80_000 ||
            !(report.StartsWith(schema + "\r\n", StringComparison.Ordinal) ||
              report.StartsWith(schema + "\n", StringComparison.Ordinal)))
            throw new InvalidDataException("Only bounded, validated signature evidence can be saved.");
        string path = Path.GetFullPath(destination);
        if (!Path.GetExtension(path).Equals(".txt", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Signature evidence must be saved as a .txt file.");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(report);
    }
}
