using System.Text;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Read-only report for one imported entry. Version hints come from comments,
/// not an authenticated catalog, and never authorize a protected edit.
/// </summary>
public sealed record ImportedProfileCheck(
    int Index, string Label, string Architecture, string WindowsHint,
    string OsBuildHint, string DllVersionHint, string Bytes, string Offsets,
    string Verdict, PatchState State, bool VersionHintCompatible, bool ExactReady)
{
    public string Description => "Entry " + (Index + 1) + " — " + Label + Environment.NewLine +
        "Windows: " + WindowsHint + Environment.NewLine +
        "OS build: " + OsBuildHint + Environment.NewLine +
        "DLL: " + DllVersionHint + Environment.NewLine +
        "Bytes: " + Bytes + Environment.NewLine +
        "Offsets: " + Offsets + Environment.NewLine +
        Verdict + Environment.NewLine +
        "The actual signature and executable-section safety checks are required for Apply.";
}

public sealed record ImportedCatalogReport(IReadOnlyList<ImportedProfileCheck> Results,
    int ExactMatches, int VersionHintMatches, int? SuggestedIndex, string Summary)
{
    public string AsText()
    {
        var text = new StringBuilder();
        text.AppendLine("Imported patterns — read-only full-catalog inspection");
        text.AppendLine(Summary);
        foreach (var candidate in Results) text.AppendLine(candidate.Description);
        return text.ToString();
    }
}

public static class ImportedCatalogInspector
{
    private static readonly Regex WindowsFamily = new(
        @"\bWindows\s+(?<family>10|11|Server)(?:\s+(?<server>20\d\d))?\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Release = new(
        @"\b(?<release>(?:\d{2}H[12]|2004|1903|1909|1809|1803|1709))\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Build = new(
        @"\b(?<build>\d{5})(?:\.(?<revision>\d{1,6}))?\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex DllVersion = new(
        @"^\s*\d+\.\d+\.(?<build>\d+)\.(?<revision>\d+)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static ImportedCatalogReport Inspect(
        byte[] dll, string dllVersion, WindowsDetails os,
        IReadOnlyList<PatchProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(dll);
        ArgumentNullException.ThrowIfNull(os);
        ArgumentNullException.ThrowIfNull(profiles);
        var checks = new List<ImportedProfileCheck>(profiles.Count);
        var exactIndices = new List<int>();
        int hintsMatching = 0;
        string architecture = os.Is64Bit ? "x64" : "x86";

        for (int index = 0; index < profiles.Count; index++)
        {
            var profile = profiles[index];
            bool incompatible = false;
            bool anyHint = false, verifiedHint = false;
            var family = WindowsFamily.Match(profile.Label);
            string osHint = "No Windows edition hint";
            if (family.Success)
            {
                anyHint = true;
                bool same = family.Groups["family"].Value.Equals("Server", StringComparison.OrdinalIgnoreCase)
                    ? os.Name.StartsWith("Windows Server", StringComparison.OrdinalIgnoreCase)
                    : os.Name.Equals("Windows " + family.Groups["family"].Value,
                        StringComparison.OrdinalIgnoreCase);
                var release = Release.Match(profile.Label);
                if (release.Success)
                    same &= os.DisplayVersion.Equals(release.Groups["release"].Value,
                        StringComparison.OrdinalIgnoreCase);
                incompatible |= !same;
                verifiedHint |= same;
                osHint = same ? "Match: " + os.Name + " " + os.DisplayVersion :
                    "Different OS/release: pattern label says " + family.Value;
            }

            var build = Build.Match(profile.Label);
            var actualDll = DllVersion.Match(dllVersion);
            string osBuild = "No build hint";
            string dllHint = "No DLL version hint";
            if (build.Success)
            {
                anyHint = true;
                int labelBuild = int.Parse(build.Groups["build"].Value,
                    System.Globalization.CultureInfo.InvariantCulture);
                int? labelUbr = build.Groups["revision"].Success
                    ? int.Parse(build.Groups["revision"].Value,
                        System.Globalization.CultureInfo.InvariantCulture) : null;
                bool osSame = os.Build == labelBuild &&
                    (!labelUbr.HasValue || os.Ubr == labelUbr.Value);
                osBuild = osSame
                    ? "Match: " + os.Build + "." + os.Ubr
                    : "Different: label " + build.Value + ", OS " + os.Build + "." + os.Ubr;
                // A Windows OS build may legitimately differ from termsrv.dll
                // build after a component update: surface both independently.
                bool dllSame = actualDll.Success &&
                    int.TryParse(actualDll.Groups["build"].Value, out int dllBuild) &&
                    dllBuild == labelBuild &&
                    (!labelUbr.HasValue ||
                     int.TryParse(actualDll.Groups["revision"].Value, out int revision) &&
                     revision == labelUbr.Value);
                dllHint = !actualDll.Success
                    ? "DLL version unreadable; build hint not verified"
                    : dllSame ? "Match: DLL " + dllVersion
                              : "Different: label " + build.Value + ", DLL " + dllVersion;
                incompatible |= !osSame && !dllSame;
                verifiedHint |= osSame || dllSame;
            }

            bool exact = false;
            PatchState state;
            string offsets = "(none)";
            string bytesText;
            if (profile.Architecture != architecture)
            {
                state = PatchState.Unsupported;
                bytesText = "Wrong architecture; file not patched";
            }
            else
            {
                var plan = PatchCatalog.Inspect(dll, "termsrv.dll", dllVersion,
                    SystemInfo.Sha256(dll), true, [profile], architecture, manual: true);
                state = plan.State;
                offsets = plan.Edits.Count == 0 ? "(none)"
                    : string.Join(", ", plan.Edits.Select(edit => "0x" + edit.Offset.ToString("X8")));
                bytesText = plan.State switch
                {
                    PatchState.Ready => "Exact original bytes present (read-only)",
                    PatchState.AlreadyPatched => "Exact replacement bytes present",
                    PatchState.Ambiguous => "Ambiguous/duplicate or mixed signature bytes",
                    PatchState.Unknown => "Exact byte pattern absent",
                    _ => "Not usable"
                };
                if (state == PatchState.Ready)
                {
                    try
                    {
                        PeSafety.RequireExecutableEdits(dll, plan.Edits);
                        exact = true;
                    }
                    catch (InvalidDataException)
                    {
                        state = PatchState.Unsupported;
                        bytesText = "Bytes present, but not within valid executable PE sections";
                    }
                }
            }

            bool hintsCompatible = !incompatible && (!anyHint || verifiedHint);
            string verdict = exact
                ? incompatible
                    ? "Exact bytes, but OS/build metadata conflict; review manually."
                    : "Verified byte pattern in executable section. Preview can be checked manually."
                : state == PatchState.AlreadyPatched
                    ? "Replacement bytes already present; no changes needed."
                    : anyHint && !incompatible && verifiedHint
                        ? "Metadata looks compatible, but file bytes are NOT a verified patch."
                        : "Not a verified candidate for this installed DLL.";
            if (exact) exactIndices.Add(index);
            if (anyHint && verifiedHint && !incompatible) hintsMatching++;
            checks.Add(new(index, profile.Label, profile.Architecture, osHint,
                osBuild, dllHint, bytesText, offsets, verdict, state,
                hintsCompatible, exact));
        }

        // A single exact, architecture-safe profile is an inspection suggestion,
        // not permission to patch. Importing multiple matches remains a choice
        // for a human; none are auto-applied or silently trusted by their label.
        int[] safe = checks.Where(r => r.ExactReady && r.VersionHintCompatible)
            .Select(r => r.Index).ToArray();
        int? suggested = exactIndices.Count == 1 && safe.Length == 1 ? safe[0] : null;
        var ordered = checks.OrderBy(r => r.ExactReady && r.VersionHintCompatible ? 0 :
                r.ExactReady ? 1 :
                r.State == PatchState.AlreadyPatched ? 2 :
                r.VersionHintCompatible && r.State != PatchState.Unknown ? 3 :
                r.State == PatchState.Unknown && r.VersionHintCompatible ? 4 : 5)
            .ThenBy(r => r.Index).ToArray();
        string summary = profiles.Count + " imported profile(s), " +
            exactIndices.Count + " exact executable byte match(es), " +
            hintsMatching + " compatible version-hint(s). " +
            (suggested.HasValue
                ? "Entry " + (suggested.Value + 1) + " is the sole verified suggested profile; Check selected before Apply."
                : exactIndices.Count > 1
                    ? "Multiple byte-valid entries: no automatic selection; inspect conflicts."
                    : "No uniquely verified version-compatible profile; labels alone are not enough.");
        return new(ordered, exactIndices.Count, hintsMatching, suggested, summary);
    }
}
