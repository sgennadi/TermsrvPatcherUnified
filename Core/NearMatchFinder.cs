namespace TermsrvPatcherUnified.Core;

// Read-only hints for an unknown DLL. Similarity NEVER authorizes a write.
public sealed record SimilarSignature(string Profile, int GroupNumber, int Offset,
    int MatchedBytes, int FixedBytes, IReadOnlyList<int> DifferentByteIndexes);

public static class NearMatchFinder
{
    public static IReadOnlyList<SimilarSignature> Find(byte[] dll,
        IReadOnlyList<PatchProfile> profiles, int maxResults = 10)
    {
        if (maxResults <= 0 || dll.Length == 0) return [];
        var results = new List<SimilarSignature>();
        foreach (var profile in profiles.Where(p => p.Architecture == "x64"))
        {
            for (int groupIndex = 0; groupIndex < profile.Groups.Count; groupIndex++)
            {
                var search = profile.Groups[groupIndex].Search;
                if (search.Length > dll.Length) continue;
                var fixedCount = search.Count(b => b.HasValue);
                if (fixedCount < 8) continue; // Too little evidence for a useful hint.

                // Exact 4-byte anchors limit candidate positions; no full-DLL fuzzy patch search.
                var anchors = new List<(int Index, byte[] Bytes, int Score)>();
                for (int i = 0; i <= search.Length - 4; i++)
                {
                    if (!search.Skip(i).Take(4).All(b => b.HasValue)) continue;
                    var part = search.Skip(i).Take(4).Select(b => b!.Value).ToArray();
                    int score = part.Distinct().Count() * 5 - part.Count(b => b == 0);
                    anchors.Add((i, part, score));
                }
                var candidates = new HashSet<int>();
                foreach (var anchor in anchors.OrderByDescending(a => a.Score).Take(8))
                {
                    foreach (var hit in BytePattern.FindOffsets(dll, anchor.Bytes, maxResults: 512))
                    {
                        int start = hit - anchor.Index;
                        if (start >= 0 && start <= dll.Length - search.Length) candidates.Add(start);
                    }
                }
                foreach (int offset in candidates)
                {
                    var different = new List<int>();
                    for (int i = 0; i < search.Length; i++)
                    {
                        if (search[i].HasValue && dll[offset + i] != search[i]!.Value)
                        {
                            different.Add(i);
                            if (different.Count > 3) break;
                        }
                    }
                    // Exact matches belong in the automatic inspector, not a near-match list.
                    if (different.Count is < 1 or > 3) continue;
                    results.Add(new SimilarSignature(profile.Label, groupIndex + 1, offset,
                        fixedCount - different.Count, fixedCount, different));
                }
            }
        }
        return results.OrderBy(r => r.DifferentByteIndexes.Count)
            .ThenByDescending(r => r.MatchedBytes)
            .ThenBy(r => r.Offset)
            .Take(maxResults).ToArray();
    }
}
