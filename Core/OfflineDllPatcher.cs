using System.Diagnostics;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Only user-selected, byte-for-byte independent files can be patched here.
/// The source is NEVER overwritten, NSudo is NEVER loaded, and TermService is
/// NEVER stopped. x86 and x64 are determined from the selected DLL's PE header.
/// </summary>
internal sealed record OfflineDllPreview(
    string SourcePath, string Architecture, string FileVersion,
    string OriginalSha256, string OriginalCrc32,
    string? PredictedSha256, string? PredictedCrc32, PatchPlan Plan)
{
    internal string Summary()
    {
        var s = new System.Text.StringBuilder()
            .AppendLine("OFFLINE DLL — no services or protected files modified")
            .AppendLine($"File: {Path.GetFileName(SourcePath)}")
            .AppendLine($"Architecture: {Architecture}")
            .AppendLine($"File version: {FileVersion}")
            .AppendLine($"State: {Plan.State}")
            .AppendLine($"Profile: {Plan.ProfileId}")
            .AppendLine($"Original CRC32: {OriginalCrc32}")
            .AppendLine($"Original SHA-256: {OriginalSha256}")
            .AppendLine($"Patched CRC32: {PredictedCrc32 ?? "(not available)"}")
            .AppendLine($"Patched SHA-256: {PredictedSha256 ?? "(not available)"}");
        foreach (var edit in Plan.Edits)
        {
            s.AppendLine($"Offset 0x{edit.Offset:X8}:");
            s.AppendLine("  Before: " + Convert.ToHexString(edit.Expected));
            s.AppendLine("  After:  " + Convert.ToHexString(edit.Replacement));
        }
        s.AppendLine(Plan.Description);
        if (Plan.State != PatchState.Ready)
            s.AppendLine("NO PATCH. Unknown/ambiguous signatures are never guessed.");
        return s.ToString();
    }
}

internal sealed record OfflineDllResult(
    string OutputPath, OfflineDllPreview Preview, string FinalSha256, string FinalCrc32)
{
    internal OfflineFixMetadata PublicMetadata() => OfflineFixMetadata.FromCompletedFile(this);
}

internal static class OfflineDllPatcher
{
    internal static OfflineDllPreview Inspect(
        string sourcePath, string? findHex = null, string? replaceHex = null)
    {
        var source = Path.GetFullPath(sourcePath);
        if (!Path.GetFileName(source).Equals("termsrv.dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Select a file named termsrv.dll.");
        var bytes = File.ReadAllBytes(source);
        var layout = PeSafety.ReadOfflineDllSections(bytes);
        bool hasFind = !string.IsNullOrWhiteSpace(findHex);
        bool hasReplace = !string.IsNullOrWhiteSpace(replaceHex);
        if (hasFind != hasReplace)
            throw new FormatException("Supply both Find HEX and Replace HEX, or leave both empty.");
        var manual = hasFind;
        var patterns = manual
            ? new[] { PatchCatalog.Manual(findHex!, replaceHex!, layout.Architecture) }
            : PatchCatalog.LoadAutomatic().Where(p => p.Architecture == layout.Architecture).ToArray();
        string version = FileVersionInfo.GetVersionInfo(source).FileVersion ?? "Unknown";
        string originalHash = SystemInfo.Sha256(bytes);
        var plan = PatchCatalog.Inspect(bytes, source, version, originalHash,
            supported: true, patterns, layout.Architecture, manual);
        if (plan.State == PatchState.Ready)
        {
            try
            {
                PeSafety.RequireOfflineExecutableEdits(bytes, plan.Edits, layout.Architecture);
            }
            catch (InvalidDataException ex)
            {
                plan = plan with
                {
                    State = PatchState.Unsupported,
                    Description = "PE code-section validation rejected candidate: " + ex.Message,
                    Edits = [],
                    PatchedBytes = null
                };
            }
        }
        return new OfflineDllPreview(source, layout.Architecture, version,
            originalHash, Crc32Hex(bytes),
            plan.PatchedBytes is not null ? SystemInfo.Sha256(plan.PatchedBytes) : null,
            plan.PatchedBytes is not null ? Crc32Hex(plan.PatchedBytes) : null, plan);
    }

    internal static OfflineDllResult SavePatched(OfflineDllPreview preview, string destination)
    {
        if (preview.Plan.State != PatchState.Ready ||
            preview.Plan.PatchedBytes is null ||
            preview.Plan.Edits.Count is < 1 or > 16)
            throw new InvalidOperationException("No uniquely verified patch for the selected DLL.");
        var source = Path.GetFullPath(preview.SourcePath);
        var output = Path.GetFullPath(destination);
        if (!Path.GetExtension(output).Equals(".dll", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Output must be a DLL.");
        if (source.Equals(output, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Offline mode never overwrites the original DLL.");
        if (Path.GetFileName(output).Equals("termsrv.dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "Save as a separate *.patched.dll; do not replace an existing termsrv.dll.");
        // Prevent an offline output from being placed in protected Windows folders.
        string windows = Path.GetFullPath(Environment.GetFolderPath(
            Environment.SpecialFolder.Windows)).TrimEnd(Path.DirectorySeparatorChar);
        if (output.StartsWith(windows + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Writing into the Windows directory is not an offline operation.");

        // Re-read and rebuild the *exact* verified edits immediately before
        // writing. A stale preview or mismatching PE architecture fails closed.
        var before = File.ReadAllBytes(source);
        if (SystemInfo.Sha256(before) != preview.OriginalSha256 ||
            Crc32Hex(before) != preview.OriginalCrc32)
            throw new InvalidOperationException("Selected DLL changed since inspection. Recheck the file.");
        PeSafety.RequireOfflineExecutableEdits(before, preview.Plan.Edits, preview.Architecture);
        var modified = (byte[])before.Clone();
        int previousEnd = 0;
        foreach (var edit in preview.Plan.Edits.OrderBy(e => e.Offset))
        {
            if (edit.Offset < previousEnd || edit.Expected.Length is < 1 or > 64 ||
                edit.Expected.Length != edit.Replacement.Length ||
                edit.Offset < 0 || edit.Offset > before.Length - edit.Expected.Length ||
                !before.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                throw new InvalidDataException("Offline edit is outside the verified preview.");
            edit.Replacement.CopyTo(modified, edit.Offset);
            previousEnd = checked(edit.Offset + edit.Expected.Length);
        }
        if (!modified.SequenceEqual(preview.Plan.PatchedBytes) ||
            SystemInfo.Sha256(modified) != preview.PredictedSha256 ||
            Crc32Hex(modified) != preview.PredictedCrc32)
            throw new InvalidDataException("Offline output differs from the verified patch plan.");

        string dir = Path.GetDirectoryName(output)
            ?? throw new ArgumentException("Destination has no parent directory.");
        if (!Directory.Exists(dir))
            throw new DirectoryNotFoundException("Choose an existing output directory.");
        if (File.Exists(output))
            throw new IOException("Destination already exists; no files were overwritten.");
        string temporary = Path.Combine(dir,
            ".termsrv-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 65536, FileOptions.WriteThrough))
            {
                file.Write(modified);
                file.Flush(flushToDisk: true);
            }
            if (SystemInfo.Sha256(File.ReadAllBytes(temporary)) != preview.PredictedSha256)
                throw new IOException("Offline temporary DLL failed checksum verification.");
            File.Move(temporary, output, overwrite: false);
            if (SystemInfo.Sha256(File.ReadAllBytes(output)) != preview.PredictedSha256)
                throw new IOException("Offline output checksum verification failed.");
            return new OfflineDllResult(output, preview,
                preview.PredictedSha256!, preview.PredictedCrc32!);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static string Crc32Hex(ReadOnlySpan<byte> bytes)
    {
        uint checksum = 0xffffffff;
        foreach (byte value in bytes)
        {
            checksum ^= value;
            for (int bit = 0; bit < 8; bit++)
                checksum = (checksum >> 1) ^ ((checksum & 1) != 0 ? 0xedb88320U : 0U);
        }
        return (~checksum).ToString("X8", System.Globalization.CultureInfo.InvariantCulture);
    }
}
