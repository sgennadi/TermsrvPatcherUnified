using System.Text;

namespace TermsrvPatcherUnified.Core;

/// <summary>Exact catalog evidence from file bytes. Diagnostic rows never authorize a write.</summary>
public sealed record SignatureGroupFinding(
    string Profile, int Group, string State, string FindHex, string ReplaceHex,
    string FindHits, string ReplaceHits, string FindOffsets, string ReplaceOffsets);

/// <summary>Profile-level evidence, without guessing which byte sequence should be modified.</summary>
public sealed record SignatureProfileFinding(
    string Profile, string Classification, string Offsets, int FixedBytes, int Groups);

public sealed record SignatureInspection(
    IReadOnlyList<SignatureGroupFinding> Rows, string Summary)
{
    public IReadOnlyList<SignatureProfileFinding> Profiles { get; init; } = [];
    public string AmbiguityReason { get; init; } = "";
    public int CompleteProfileCount { get; init; }
    public int DistinctCandidateTargetCount { get; init; }
    public int ConflictingProfileCount { get; init; }

    public string AsText()
    {
        var builder = new StringBuilder();
        builder.AppendLine("Automatic signature evidence (READ ONLY)");
        builder.AppendLine(Summary);
        builder.AppendLine();
        builder.AppendLine("Per-profile classification:");
        foreach (var profile in Profiles)
            builder.AppendLine("  " + profile.Profile + " — " + profile.Classification +
                "; offsets " + profile.Offsets + "; fixed bytes " + profile.FixedBytes +
                "; groups " + profile.Groups);
        builder.AppendLine();
        builder.AppendLine("Per-group exact evidence:");
        foreach (var row in Rows)
        {
            builder.AppendLine();
            builder.AppendLine(row.Profile + " / group " + row.Group + " — " + row.State);
            builder.AppendLine("  Find:    " + row.FindHex);
            builder.AppendLine("  Replace: " + row.ReplaceHex);
            builder.AppendLine("  Exact Find hits: " + row.FindHits + " at " + row.FindOffsets);
            builder.AppendLine("  Exact Replace hits: " + row.ReplaceHits + " at " + row.ReplaceOffsets);
        }
        builder.AppendLine("Profile label or fixed-byte count is NOT proof that a matching location may be modified.");
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
        var profileFindings = new List<SignatureProfileFinding>();
        var distinctTargets = new HashSet<string>(StringComparer.Ordinal);
        int complete = 0, invalid = 0, mixed = 0;
        foreach (var profile in profiles.Where(p => p.Architecture == architecture))
        {
            bool everyOriginal = profile.Groups.Count > 0;
            bool everyReplacement = profile.Groups.Count > 0;
            bool everyPresent = profile.Groups.Count > 0;
            bool hasCollision = false;
            int fixedBytes = 0;
            var matchedTargets = new List<(int Offset, int Length, string Replacement)>();

            for (int index = 0; index < profile.Groups.Count; index++)
            {
                var group = profile.Groups[index];
                fixedBytes += group.Search.Count(x => x.HasValue);
                var before = BytePattern.FindOffsets(file, group.Search,
                    maxResults: MaxRecordedPerPattern + 1);
                var after = BytePattern.FindOffsets(file, group.Replace,
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

                if (originalOnly || replacementOnly)
                {
                    matchedTargets.Add((originalOnly ? before[0] : after[0],
                        group.Replace.Length, Convert.ToHexString(group.Replace)));
                }

                findings.Add(new SignatureGroupFinding(
                    profile.Label, index + 1, state,
                    string.Join(" ", group.Search.Select(x =>
                        x.HasValue ? x.Value.ToString("X2") : "*")),
                    string.Join(" ", group.Replace.Select(x => x.ToString("X2"))),
                    Count(before), Count(after), Locations(before), Locations(after)));
            }

            var sorted = matchedTargets.OrderBy(x => x.Offset).ToArray();
            for (int i = 1; i < sorted.Length; i++)
                if ((long)sorted[i].Offset < (long)sorted[i - 1].Offset + sorted[i - 1].Length)
                    hasCollision = true;

            string classification;
            if (hasCollision)
            {
                invalid++;
                classification = "WITHIN-PROFILE conflict: repeat, Find/Replace overlap, or intersecting groups";
            }
            else if (everyOriginal || everyReplacement)
            {
                complete++;
                classification = everyOriginal ? "Complete original match" : "Complete replacement match";
                string signature = (everyOriginal ? "Original|" : "Replacement|") +
                    string.Join(";", sorted.Select(x => x.Offset + ":" + x.Replacement));
                distinctTargets.Add(signature);
            }
            else if (everyPresent)
            {
                invalid++;
                mixed++;
                classification = "WITHIN-PROFILE conflict: mixed original/replacement groups";
            }
            else
            {
                classification = "Incomplete: one or more groups absent";
            }

            profileFindings.Add(new SignatureProfileFinding(
                profile.Label, classification,
                sorted.Length == 0 ? "(none)" :
                    string.Join(", ", sorted.Select(x => "0x" + x.Offset.ToString("X8"))),
                fixedBytes, profile.Groups.Count));
        }

        string reason;
        if (distinctTargets.Count > 1)
        {
            var completeProfiles = profileFindings.Where(x =>
                x.Classification.StartsWith("Complete ", StringComparison.Ordinal)).Take(8);
            reason = "MULTIPLE DISTINCT complete profiles at different candidate target sets: " +
                string.Join("; ", completeProfiles.Select(x =>
                    x.Profile + " [" + x.Offsets + ", fixed bytes " + x.FixedBytes + "]")) +
                ". Automatic selection requires an explicit trusted OS-context policy, a unique " +
              "specific match over only generic fallback and independent PE safety; " +
              "a longer pattern alone is not sufficient.";
        }
        else if (invalid > 0)
        {
            reason = "WITHIN-PROFILE conflict: repeated bytes, simultaneous Find/Replace, " +
                     "overlapping groups or mixed original/replacement states.";
        }
        else if (complete > 1)
        {
            reason = "Several catalog profiles resolve to the same candidate byte edits; " +
                     "they are equivalent matches, not independent target locations.";
        }
        else
        {
            reason = "No cross-profile conflict detected by exact signature inspection.";
        }

        string summary = complete + " complete profile(s), " + distinctTargets.Count +
            " distinct candidate target set(s), " + invalid + " conflicting profile(s)" +
            (mixed > 0 ? " (" + mixed + " mixed)" : "") + ". Classification: " + reason +
            " Read-only evidence only; Apply safety rules are unchanged.";
        return new SignatureInspection(findings, summary)
        {
            Profiles = profileFindings,
            AmbiguityReason = reason,
            CompleteProfileCount = complete,
            DistinctCandidateTargetCount = distinctTargets.Count,
            ConflictingProfileCount = invalid
        };
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
