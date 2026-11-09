using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>Exact catalog evidence from file bytes. Diagnostic rows never authorize a write.</summary>
public sealed record SignatureGroupFinding(
    string Profile, int Group, string State, string FindHex, string ReplaceHex,
    string FindHits, string ReplaceHits, string FindOffsets, string ReplaceOffsets);

public sealed record SignatureInspection(
    IReadOnlyList<SignatureGroupFinding> Rows, string Summary)
{
    public string AsText()
    {
        var builder = new StringBuilder();
        builder.AppendLine("Automatic signature evidence (READ ONLY)");
        builder.AppendLine(Summary);
        foreach (var row in Rows)
        {
            builder.AppendLine();
            builder.AppendLine(row.Profile + " / group " + row.Group + " — " + row.State);
            builder.AppendLine("  Find:    " + row.FindHex);
            builder.AppendLine("  Replace: " + row.ReplaceHex);
            builder.AppendLine("  Exact Find hits: " + row.FindHits + " at " + row.FindOffsets);
            builder.AppendLine("  Exact Replace hits: " + row.ReplaceHits + " at " + row.ReplaceOffsets);
        }
        builder.AppendLine("These locations are inspection evidence, not validated replacements.");
        return builder.ToString();
    }
}

public static class SignatureInspector
{
    private const int MaxRecordedPerPattern = 5;

    public static SignatureInspection Analyze(byte[] file, IReadOnlyList<PatchProfile> profiles,
        string architecture = "x64")
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(profiles);
        var findings = new List<SignatureGroupFinding>();
        int complete = 0, invalid = 0;
        foreach (var profile in profiles.Where(p => p.Architecture == architecture))
        {
            bool everyOriginal = profile.Groups.Count > 0;
            bool everyReplacement = profile.Groups.Count > 0;
            bool everyPresent = profile.Groups.Count > 0;
            bool hasCollision = false;
            for (int index = 0; index < profile.Groups.Count; index++)
            {
                var g = profile.Groups[index];
                var before = BytePattern.FindOffsets(file, g.Search,
                    maxResults: MaxRecordedPerPattern + 1);
                var after = BytePattern.FindOffsets(file, g.Replace,
                    maxResults: MaxRecordedPerPattern + 1);
                bool originalOnly = before.Count == 1 && after.Count == 0;
                bool replacementOnly = after.Count == 1 && before.Count == 0;
                everyOriginal &= originalOnly;
                everyReplacement &= replacementOnly;
                everyPresent &= originalOnly || replacementOnly;
                string state;
                if (before.Count > 0 && after.Count > 0)
                    state = "Conflict: Find and Replace both present";
                else if (before.Count > 1 || after.Count > 1)
                    state = "Ambiguous: repeated exact bytes";
                else if (originalOnly) state = "Exact original match";
                else if (replacementOnly) state = "Exact replacement match";
                else state = "Not found";
                if (state.StartsWith("Conflict:", StringComparison.Ordinal) ||
                    state.StartsWith("Ambiguous:", StringComparison.Ordinal))
                    hasCollision = true;

                findings.Add(new SignatureGroupFinding(
                    profile.Label, index + 1, state,
                    string.Join(" ", g.Search.Select(x => x.HasValue ? x.Value.ToString("X2") : "*")),
                    Convert.ToHexString(g.Replace.AsSpan()),
                    Count(before), Count(after), Locations(before), Locations(after)));
            }
            if (everyOriginal || everyReplacement) complete++;
            if (hasCollision || (everyPresent && !everyOriginal && !everyReplacement))
                invalid++;
        }
        string summary = complete + " complete profile(s); " + invalid +
            " profile(s) with collisions or mixed original/replacement groups. " +
            (complete > 1 ? "Multiple complete profiles require independent review. " : "") +
            "A partial hit does not identify a safe or licensed patch.";
        return new SignatureInspection(findings, summary);
    }

    private static string Count(IReadOnlyList<int> found)
        => found.Count > MaxRecordedPerPattern ? "more than " + MaxRecordedPerPattern :
            found.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string Locations(IReadOnlyList<int> found)
    {
        if (found.Count == 0) return "(none)";
        string displayed = string.Join(", ",
            found.Take(MaxRecordedPerPattern).Select(x => "0x" + x.ToString("X8")));
        return found.Count > MaxRecordedPerPattern ? displayed + ", ..." : displayed;
    }
}
