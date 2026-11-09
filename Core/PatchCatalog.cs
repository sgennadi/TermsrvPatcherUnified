using System.Reflection;
using System.Text;

namespace TermsrvPatcherUnified.Core;

public enum PatchState { Ready, AlreadyPatched, Unknown, Ambiguous, Unsupported }

public sealed record PatchProfile(string Label, string Architecture, IReadOnlyList<BytePattern> Groups, string Source);
public sealed record AutomaticSelectionContext(string WindowsName, string DisplayVersion, string InstallationType);
public sealed record PatchEdit(int Offset, byte[] Expected, byte[] Replacement);
public sealed record PatchPlan(PatchState State, string Description, string ProfileId, string FilePath,
    string FileVersion, string OriginalSha256, IReadOnlyList<PatchEdit> Edits, byte[]? PatchedBytes,
    bool IsManual = false);

public static class PatchCatalog
{
    public static IReadOnlyList<PatchProfile> LoadAutomatic()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("TermsrvPatcherUnified.Patterns.AutomaticPatterns.txt")
            ?? throw new FileNotFoundException("Embedded automatic catalog is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return Parse(reader.ReadToEnd(), "fabianosrc/TermsrvPatcher automatic signatures");
    }

    public static IReadOnlyList<PatchProfile> Parse(string content, string source = "Custom pattern file")
    {
        var result = new List<PatchProfile>();
        string label = "Unlabeled pattern";
        int lineNumber = 0;
        foreach (var raw in content.Split('\n'))
        {
            lineNumber++;
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('#'))
            {
                var comment = line.TrimStart('#').Trim();
                if (comment.StartsWith("Windows ", StringComparison.OrdinalIgnoreCase)) label = comment;
                continue;
            }
            var cells = line.Split(',', 3);
            if (cells.Length != 3)
                throw new FormatException($"Line {lineNumber}: expected architecture, find, replace.");
            var arch = cells[0].Trim().ToLowerInvariant();
            if (arch is not ("x86" or "x64"))
                throw new FormatException($"Line {lineNumber}: invalid architecture '{arch}'.");
            var finds = cells[1].Split('|').Select(x => x.Trim()).ToArray();
            var replacements = cells[2].Split('|').Select(x => x.Trim()).ToArray();
            if (finds.Length != replacements.Length || finds.Length == 0)
                throw new FormatException($"Line {lineNumber}: find/replace group count differs.");
            var groups = new List<BytePattern>();
            for (int i = 0; i < finds.Length; i++)
            {
                try { groups.Add(new BytePattern(finds[i], replacements[i])); }
                catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
                { throw new FormatException($"Line {lineNumber}, group {i + 1}: {ex.Message}", ex); }
            }
            result.Add(new PatchProfile(label, arch, groups, source));
        }
        return result;
    }

    public static PatchProfile Manual(string find, string replace, string architecture = "x64")
    {
        var finds = find.Split('|');
        var replacements = replace.Split('|');
        if (finds.Length != replacements.Length || finds.Length == 0)
            throw new FormatException("Find and replace must have matching '|' groups.");
        return new PatchProfile("Manual input", architecture,
            finds.Select((part, i) => new BytePattern(part, replacements[i])).ToArray(), "Manual editor");
    }

    private const string EmbeddedSource = "fabianosrc/TermsrvPatcher automatic signatures";
    private const string GenericLabel = "Windows 10 / Windows 11 22H2-23H2 / older Windows Server generic signature";

    private sealed record Candidate(string Label, List<PatchEdit> Edits, bool Already,
        bool SpecificForHost, bool GenericFallback);

    private static bool IsEmbedded(PatchProfile profile)
        => profile.Source.Equals(EmbeddedSource, StringComparison.Ordinal);

    private static bool IsGenericFallback(PatchProfile profile)
        => IsEmbedded(profile) && profile.Label.Equals(GenericLabel, StringComparison.Ordinal);

    private static bool IsSpecificForHost(PatchProfile profile, AutomaticSelectionContext? host)
    {
        if (host is null || !IsEmbedded(profile) ||
            !host.WindowsName.Equals("Windows 11", StringComparison.OrdinalIgnoreCase) ||
            !host.InstallationType.Equals("Client", StringComparison.OrdinalIgnoreCase))
            return false;
        return host.DisplayVersion.ToUpperInvariant() switch
        {
            "24H2" => profile.Label.StartsWith("Windows 11 24H2 family", StringComparison.Ordinal),
            "25H2" or "26H2" =>
                profile.Label.Equals("Windows 11 25H2 / 26H2 alternate layout", StringComparison.Ordinal),
            _ => false
        };
    }

    private static bool RegionsOverlap(Candidate selected, Candidate other)
        => selected.Edits.Any(a => other.Edits.Any(b =>
            (long)a.Offset < (long)b.Offset + b.Expected.Length &&
            (long)b.Offset < (long)a.Offset + a.Expected.Length));

    // A candidate is admitted only when every group matches exactly once and all
    // groups share a state. The installed-OS priority applies ONLY to trusted
    // embedded automatic signatures, never to imported or manually entered rules.
    // The generic fallback is not patched alongside a selected specific target.
    public static PatchPlan Inspect(byte[] dll, string path, string fileVersion, string sha256,
        bool supported, IReadOnlyList<PatchProfile> profiles, string architecture = "x64", bool manual = false,
        AutomaticSelectionContext? selectionContext = null)
    {
        if (!supported)
            return new(PatchState.Unsupported, "Unsupported target/OS. No modification permitted.", "",
                path, fileVersion, sha256, [], null, manual);
        var candidates = new Dictionary<string, Candidate>(StringComparer.Ordinal);
        bool ambiguous = false;
        foreach (var profile in profiles.Where(p => p.Architecture == architecture))
        {
            int originalCount = 0, replacedCount = 0;
            var edits = new List<PatchEdit>();
            bool missing = false;
            foreach (var group in profile.Groups)
            {
                var before = BytePattern.FindOffsets(dll, group.Search);
                var after = BytePattern.FindOffsets(dll, group.Replace);
                if (before.Count > 1 || after.Count > 1 || (before.Count == 1 && after.Count == 1))
                {
                    ambiguous = true;
                    missing = true;
                    break;
                }
                if (before.Count == 1)
                {
                    originalCount++;
                    edits.Add(new PatchEdit(before[0], dll.AsSpan(before[0], group.Replace.Length).ToArray(), group.Replace));
                }
                else if (after.Count == 1)
                {
                    replacedCount++;
                    edits.Add(new PatchEdit(after[0], group.Replace, group.Replace));
                }
                else { missing = true; break; }
            }
            if (missing) continue;
            if (originalCount > 0 && replacedCount > 0) { ambiguous = true; continue; }
            var sorted = edits.OrderBy(e => e.Offset).ToArray();
            for (int i = 1; i < sorted.Length; i++)
            {
                if (sorted[i].Offset < sorted[i - 1].Offset + sorted[i - 1].Expected.Length)
                { ambiguous = true; missing = true; break; }
            }
            if (missing) continue;
            var id = string.Join(";", sorted.Select(e => $"{e.Offset}:{Convert.ToHexString(e.Replacement)}"));
            if (candidates.TryGetValue(id, out var existing))
            {
                if (existing.Already != (originalCount == 0)) ambiguous = true;
                else candidates[id] = existing with
                {
                    Label = existing.Label + " / " + profile.Label,
                    SpecificForHost = existing.SpecificForHost || IsSpecificForHost(profile, selectionContext),
                    GenericFallback = existing.GenericFallback || IsGenericFallback(profile)
                };
            }
            else candidates[id] = new Candidate(profile.Label, edits, originalCount == 0,
                IsSpecificForHost(profile, selectionContext), IsGenericFallback(profile));
        }
        if (ambiguous)
            return new(PatchState.Ambiguous,
                "At least one signature has repeated, overlapping or mixed Find/Replace hits; no changes allowed.",
                "", path, fileVersion, sha256, [], null, manual);
        if (candidates.Count == 0)
            return new(PatchState.Unknown, "No verified signature found. Use Search DLL or Manual for inspection.",
                "", path, fileVersion, sha256, [], null, manual);

        Candidate best;
        string selectedBy = "";
        if (candidates.Count == 1)
        {
            best = candidates.Values.Single();
        }
        else
        {
            // A Windows-specific match may disambiguate a simultaneously present
            // old GENERIC fallback, but never two specific, unknown, or
            // overlapping targets. A trusted installed-OS context is mandatory.
            var specific = !manual && selectionContext is not null
                ? candidates.Values.Where(c => c.SpecificForHost).ToArray()
                : [];
            if (specific.Length != 1 ||
                candidates.Values.Any(c => !ReferenceEquals(c, specific[0]) &&
                    (!c.GenericFallback || RegionsOverlap(specific[0], c))))
            {
                return new(PatchState.Ambiguous,
                    "Multiple distinct signature targets; OS-aware priority could not uniquely select " +
                    "one trusted specific profile over only non-overlapping generic fallback matches.",
                    "", path, fileVersion, sha256, [], null, manual);
            }
            best = specific[0];
            selectedBy = "Selected the verified " + selectionContext!.WindowsName + " " +
                selectionContext.DisplayVersion + " specific profile over the matching older generic " +
                "fallback. Only the selected target is included. ";
        }
        if (best.Already)
            return new(PatchState.AlreadyPatched, selectedBy +
                "Replacement bytes already present at the selected target. No changes needed.",
                best.Label, path, fileVersion, sha256, best.Edits, null, manual);
        var output = (byte[])dll.Clone();
        foreach (var edit in best.Edits)
        {
            if (!output.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                throw new InvalidOperationException("Preview validation failed.");
            edit.Replacement.CopyTo(output, edit.Offset);
        }
        return new(PatchState.Ready, selectedBy +
            "A single verified target has been selected for preview; PE and SHA-256 checks still apply.",
            best.Label,
            path, fileVersion, sha256, best.Edits, output, manual);
    }
}
