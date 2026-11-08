using System.Reflection;
using System.Text;

namespace TermsrvPatcherUnified.Core;

public enum PatchState { Ready, AlreadyPatched, Unknown, Ambiguous, Unsupported }

public sealed record PatchProfile(string Label, string Architecture, IReadOnlyList<BytePattern> Groups, string Source);
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

    private sealed record Candidate(string Label, List<PatchEdit> Edits, bool Already);

    // A candidate may be used ONLY when every group matches exactly once and all groups share a state.
    // Unknown patterns never result in auto-generated replacement bytes.
    public static PatchPlan Inspect(byte[] dll, string path, string fileVersion, string sha256,
        bool supported, IReadOnlyList<PatchProfile> profiles, string architecture = "x64", bool manual = false)
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
                else candidates[id] = existing with { Label = existing.Label + " / " + profile.Label };
            }
            else candidates[id] = new Candidate(profile.Label, edits, originalCount == 0);
        }
        if (ambiguous || candidates.Count > 1)
            return new(PatchState.Ambiguous, "Conflicting or multiple matching signatures; no changes allowed.",
                "", path, fileVersion, sha256, [], null, manual);
        if (candidates.Count == 0)
            return new(PatchState.Unknown, "No verified signature found. Use Search DLL or Manual for inspection.",
                "", path, fileVersion, sha256, [], null, manual);
        var best = candidates.Values.Single();
        if (best.Already)
            return new(PatchState.AlreadyPatched, "Replacement bytes already present. No changes needed.",
                best.Label, path, fileVersion, sha256, best.Edits, null, manual);
        var output = (byte[])dll.Clone();
        foreach (var edit in best.Edits)
        {
            if (!output.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                throw new InvalidOperationException("Preview validation failed.");
            edit.Replacement.CopyTo(output, edit.Offset);
        }
        return new(PatchState.Ready, "Unique matching signature found. Preview is ready.", best.Label,
            path, fileVersion, sha256, best.Edits, output, manual);
    }
}
