using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Opt-in public metadata for a saved OFFLINE file. Unlike a successful
/// system Apply, this is not evidence that the file works when installed.
/// </summary>
internal sealed record OfflineFixMetadata(
    string Architecture, string DllVersion, string ApplicationVersion,
    string OriginalSha256, string OriginalCrc32,
    string PatchedSha256, string PatchedCrc32,
    IReadOnlyList<ChangedBytes> Changes)
{
    private static readonly Regex Version = new(
        @"\A[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}\z", RegexOptions.CultureInvariant);
    private static readonly Regex App = new(
        @"\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hash = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Crc = new(
        @"\A[0-9A-F]{8}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Hex = new(
        @"\A(?:[0-9A-F]{2}){1,64}\z", RegexOptions.CultureInvariant);

    internal static OfflineFixMetadata FromCompletedFile(OfflineDllResult result)
    {
        var p = result.Preview;
        var metadata = new OfflineFixMetadata(p.Architecture, p.FileVersion,
            UpdateIntegration.Version,
            p.OriginalSha256, p.OriginalCrc32,
            result.FinalSha256, result.FinalCrc32,
            p.Plan.Edits.OrderBy(x => x.Offset)
                .Select(x => new ChangedBytes(x.Offset,
                    Convert.ToHexString(x.Expected), Convert.ToHexString(x.Replacement))).ToArray());
        metadata.Validate();
        return metadata;
    }

    internal void Validate()
    {
        if (Architecture is not ("x64" or "x86") ||
            !(DllVersion == "Unknown" || Version.IsMatch(DllVersion)) ||
            !App.IsMatch(ApplicationVersion) ||
            !Hash.IsMatch(OriginalSha256) || !Hash.IsMatch(PatchedSha256) ||
            OriginalSha256 == PatchedSha256 ||
            !Crc.IsMatch(OriginalCrc32) || !Crc.IsMatch(PatchedCrc32) ||
            Changes is not { Count: > 0 and <= 16 })
            throw new InvalidDataException("Invalid offline compatibility report fields.");
        long priorEnd = 0;
        foreach (var edit in Changes.OrderBy(x => x.Offset))
        {
            if (edit.Offset < priorEnd || edit.Offset > uint.MaxValue ||
                !Hex.IsMatch(edit.Before) || !Hex.IsMatch(edit.After) ||
                edit.Before == edit.After || edit.Before.Length != edit.After.Length)
                throw new InvalidDataException("Invalid offline byte-range metadata.");
            priorEnd = checked(edit.Offset + edit.Before.Length / 2);
        }
    }

    internal string AsComment()
    {
        Validate();
        var edits = string.Join("|", Changes.OrderBy(x => x.Offset)
            .Select(x => $"0x{x.Offset:X8}:{x.Before}>{x.After}"));
        return "termsrv-offline/v1\n" +
               $"architecture={Architecture}\n" +
               "file=termsrv.dll\n" +
               $"dll={DllVersion}\n" +
               $"app={ApplicationVersion}\n" +
               $"original_sha256={OriginalSha256}\n" +
               $"original_crc32={OriginalCrc32}\n" +
               $"patched_sha256={PatchedSha256}\n" +
               $"patched_crc32={PatchedCrc32}\n" +
               $"edits={edits}";
    }
}
