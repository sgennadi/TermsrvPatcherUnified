using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Read-only ranked evidence for Automatic. This class has no mutation methods.
/// Only PatchCatalog / TermsrvEngine can produce a protected Apply plan.
/// </summary>
public sealed record AutomaticPriorityRow(
    int Order, string Profile, string Name, string Match, string Offsets,
    string Decision, string Reason, string FindHex, string ReplaceHex,
    bool ReferenceOnly);

public sealed record AutomaticPriorityReport(
    IReadOnlyList<AutomaticPriorityRow> Rows, string Summary);

internal static class AutomaticPriorityPolicy
{
    private const string EmbeddedSource = "fabianosrc/TermsrvPatcher automatic signatures";
    private const string GenericLabel =
        "Windows 10 / Windows 11 22H2-23H2 / older Windows Server generic signature";
    private const string Family24 = "Windows 11 24H2 family";
    private const string Family2526 = "Windows 11 25H2 / 26H2 alternate layout";

    // External source (haojiezhe12345/termsrv-multiuser-patcher): a one-byte
    // in-memory branch change, not verified for our on-disk Apply workflow.
    // It is deliberately excluded from PatchCatalog.LoadAutomatic().
    private const string ReferenceLabel = "External 12-byte hotpatch (INSPECTION ONLY)";
    private static readonly BytePattern HotpatchReference = new(
        "44 8B 8F 38 06 00 00 45 3B C1 75 14",
        "44 8B 8F 38 06 00 00 45 3B C1 EB 14");

    private sealed record Ranked(int Weight, int SourceOrder, AutomaticPriorityRow Row);

    internal static AutomaticPriorityReport Build(
        WindowsDetails host, PatchPlan plan, VerifiedSignatureSnapshot snapshot,
        IReadOnlyList<PatchProfile> catalog)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(catalog);
        if (!snapshot.Sha256.Equals(plan.OriginalSha256, StringComparison.OrdinalIgnoreCase) ||
            !SystemInfo.Sha256(snapshot.Bytes).Equals(snapshot.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Automatic priority evidence does not match checked DLL SHA-256.");

        var priority = new List<Ranked>();
        int index = 0;
        foreach (var profile in catalog)
        {
            if (profile.Architecture != (host.Is64Bit ? "x64" : "x86")) continue;
            // An imported profile must never acquire the trusted Automatic label.
            if (profile.Source != EmbeddedSource)
                throw new InvalidDataException("Automatic priority list requires the embedded catalog only.");

            var group = snapshot.Inspection.Rows.Where(x => x.Profile == profile.Label).ToArray();
            var finding = snapshot.Inspection.Profiles.FirstOrDefault(x => x.Profile == profile.Label);
            if (group.Length != profile.Groups.Count || finding is null)
                throw new InvalidDataException("Automatic priority list is missing exact signature evidence.");

            bool complete = finding.Classification.StartsWith("Complete ", StringComparison.Ordinal);
            bool original = finding.Classification == "Complete original match";
            bool already = finding.Classification == "Complete replacement match";
            bool chosen = complete && (plan.State is PatchState.Ready or PatchState.AlreadyPatched) &&
                          plan.ProfileId.Equals(profile.Label, StringComparison.Ordinal);
            bool server = !host.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase);
            string decision, reason;
            if (finding.Classification.StartsWith("WITHIN-PROFILE", StringComparison.Ordinal))
            {
                decision = "Blocked";
                reason = "Repeated, mixed or intersecting bytes; never auto-select.";
            }
            else if (!complete)
            {
                decision = "Not found";
                reason = "No complete exact signature on the checked DLL.";
            }
            else if (server || plan.State == PatchState.Unsupported)
            {
                decision = "Inspect only";
                reason = server ? "Windows Server: protected Apply is disabled." :
                    "This OS/file failed protected Apply eligibility.";
            }
            else if (plan.State == PatchState.Ambiguous)
            {
                decision = "Blocked";
                reason = "Competing exact targets; priority cannot override a safety conflict.";
            }
            else if (chosen)
            {
                decision = plan.State == PatchState.Ready ? "Selected" : "Already patched";
                reason = plan.State == PatchState.Ready
                    ? "Only this exact target is present in the verified Apply preview."
                    : "Selected replacement bytes already exist; no edit is planned.";
            }
            else
            {
                decision = "Skipped";
                reason = IsGeneric(profile)
                    ? "A specific trusted target was selected; Generic is not a second edit."
                    : "Another target was selected; no sequential multi-patching.";
            }

            string match = string.Join("; ", group.Select(x =>
                "F:" + x.FindHits + " R:" + x.ReplaceHits));
            var row = new AutomaticPriorityRow(
                0, profile.Label, FriendlyName(profile), match, finding.Offsets,
                decision, reason, group[0].FindHex, group[0].ReplaceHex, false);
            priority.Add(new(Rank(profile, host), index++, row));
        }

        // This reference is visible only as evidence, never as a fourth Apply rule.
        if (host.Is64Bit)
        {
            var before = BytePattern.FindOffsets(snapshot.Bytes, HotpatchReference.Search, maxResults: 3);
            var after = BytePattern.FindOffsets(snapshot.Bytes, HotpatchReference.Replace, maxResults: 3);
            string offsets = FormatOffsets(before.Count > 0 ? before : after);
            string explanation = before.Count == 1 && after.Count == 0
                ? "Exact reference bytes found. Memory-only upstream method; not eligible for disk Apply."
                : after.Count == 1 && before.Count == 0
                    ? "Reference replacement found. Not evidence of an installed file patch."
                    : before.Count + after.Count == 0
                        ? "External reference not found; no modification is proposed."
                        : "Repeated or mixed reference bytes; observation only.";
            var row = new AutomaticPriorityRow(
                0, ReferenceLabel, "Hotpatch reference · 12 bytes (read-only)",
                "F:" + before.Count + " R:" + after.Count, offsets,
                "Reference only", explanation,
                string.Join(" ", HotpatchReference.Search.Select(x => x!.Value.ToString("X2"))),
                string.Join(" ", HotpatchReference.Replace.Select(x => x.ToString("X2"))), true);
            priority.Add(new(RankHotpatch(host), index, row));
        }

        var ordered = priority.OrderBy(x => x.Weight).ThenBy(x => x.SourceOrder)
            .Select((x, i) => x.Row with { Order = i + 1 }).ToArray();
        var selected = ordered.FirstOrDefault(x => x.Decision is "Selected" or "Already patched");
        string summary = selected is null
            ? "No eligible Apply target selected (" + plan.State + "). Exact Find/Replace hits are inspection evidence."
            : "Priority #" + selected.Order + " selected: " + selected.Name +
              ". At most one verified target is proposed; lower rows are never patched in sequence.";
        return new AutomaticPriorityReport(ordered, summary);
    }

    private static string FriendlyName(PatchProfile profile)
        => IsGeneric(profile) ? "Generic · 12 bytes" :
           profile.Label.StartsWith(Family24, StringComparison.Ordinal) ? "24H2 family · 13 bytes" :
           profile.Label.Equals(Family2526, StringComparison.Ordinal) ? "25H2 / 26H2 · 19 bytes" :
           profile.Label;

    private static bool IsGeneric(PatchProfile profile)
        => profile.Label.Equals(GenericLabel, StringComparison.Ordinal);

    private static int Rank(PatchProfile profile, WindowsDetails host)
    {
        bool client11 = host.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase) &&
                        host.Name.Equals("Windows 11", StringComparison.OrdinalIgnoreCase);
        if (client11 && host.DisplayVersion.Equals("24H2", StringComparison.OrdinalIgnoreCase))
            return profile.Label.StartsWith(Family24, StringComparison.Ordinal) ? 10 :
                   IsGeneric(profile) ? 20 : 30;
        if (client11 && (host.DisplayVersion.Equals("25H2", StringComparison.OrdinalIgnoreCase) ||
                         host.DisplayVersion.Equals("26H2", StringComparison.OrdinalIgnoreCase)))
            return profile.Label.Equals(Family2526, StringComparison.Ordinal) ? 10 :
                   IsGeneric(profile) ? 20 : 30;
        // Server 2025 gets a useful read-only order based on its 26100 DLL
        // family; it does not inherit Windows 11 Apply authorization.
        if (!host.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase) &&
            host.Build >= 26100)
            return profile.Label.StartsWith(Family24, StringComparison.Ordinal) ? 10 :
                   profile.Label.Equals(Family2526, StringComparison.Ordinal) ? 20 : 30;
        return IsGeneric(profile) ? 10 :
               profile.Label.StartsWith(Family24, StringComparison.Ordinal) ? 30 : 35;
    }

    private static int RankHotpatch(WindowsDetails host)
        => host.Name.Equals("Windows 11", StringComparison.OrdinalIgnoreCase) &&
           host.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase) &&
           (host.DisplayVersion.Equals("25H2", StringComparison.OrdinalIgnoreCase) ||
            host.DisplayVersion.Equals("26H2", StringComparison.OrdinalIgnoreCase)) ? 15 : 40;

    private static string FormatOffsets(IReadOnlyList<int> offsets)
        => offsets.Count == 0 ? "(none)" :
           string.Join(", ", offsets.Select(x => "0x" + x.ToString("X8")));
}
