using System.Buffers.Binary;
using System.IO;
using System.Text;
using TermsrvPatcherUnified.Core;

internal static class OfflineDllTests
{
    private static int checks;
    private static void Check(bool value, string what)
    {
        checks++;
        if (!value) throw new Exception("Offline DLL QA: " + what);
    }
    private static void Refuses<T>(Action action, string what) where T : Exception
    {
        try { action(); }
        catch (T) { checks++; return; }
        throw new Exception("Offline DLL QA did not reject: " + what);
    }

    private static byte[] SyntheticDll(bool x64, int match = 0x220)
    {
        var bytes = new byte[0x600];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C, 4), 0x80);
        new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(bytes, 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2), x64 ? (ushort)0x8664 : (ushort)0x014C);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x86, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x94, 2), x64 ? (ushort)0xF0 : (ushort)0xE0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x96, 2), 0x2000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x98, 2), x64 ? (ushort)0x20B : (ushort)0x10B);
        int section = 0x80 + 24 + (x64 ? 0xF0 : 0xE0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 20, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(section + 36, 4), 0x60000020);
        new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(bytes, match);
        return bytes;
    }

    internal static int Run()
    {
        Check(OfflineDllPatcher.Crc32Hex(Encoding.ASCII.GetBytes("123456789")) == "CBF43926",
            "CRC32 matches published IEEE reference vector.");
        string root = Path.Combine(Path.GetTempPath(), "Termsrv-OfflineQA-" +
            Guid.NewGuid().ToString("N"));
        try
        {
            foreach (bool x64 in new[] { false, true })
            {
                string directory = Path.Combine(root, x64 ? "amd64" : "i386");
                Directory.CreateDirectory(directory);
                string input = Path.Combine(directory, "termsrv.dll");
                string output = Path.Combine(directory, "termsrv.patched.dll");
                var original = SyntheticDll(x64);
                File.WriteAllBytes(input, original);
                var layout = PeSafety.ReadOfflineDllSections(original);
                Check(layout.Architecture == (x64 ? "x64" : "x86"),
                    "PE architecture is read from DLL headers.");
                if (!x64)
                    Refuses<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(original),
                        "x86 is not accepted by protected AMD64 writer.");
                var noAutomatic = OfflineDllPatcher.Inspect(input);
                if (!x64)
                    Check(noAutomatic.Plan.State == PatchState.Unknown,
                        "x86 has no invented automatic signatures.");

                var preview = OfflineDllPatcher.Inspect(input, "11 22 33 44", "AA BB CC DD");
                Check(preview.Architecture == layout.Architecture &&
                      preview.Plan.State == PatchState.Ready,
                    "unique manual pattern is checked in executable section.");
                Check(preview.OriginalSha256 == SystemInfo.Sha256(original) &&
                      preview.OriginalCrc32 == OfflineDllPatcher.Crc32Hex(original),
                    "source SHA-256 and CRC32 are independently checked.");
                Check(preview.PredictedSha256 != preview.OriginalSha256,
                    "preview predicts a different SHA-256.");
                var saved = OfflineDllPatcher.SavePatched(preview, output);
                var modified = File.ReadAllBytes(output);
                Check(original.SequenceEqual(File.ReadAllBytes(input)),
                    "original DLL bytes remain unchanged.");
                Check(saved.FinalSha256 == SystemInfo.Sha256(modified) &&
                      saved.FinalCrc32 == OfflineDllPatcher.Crc32Hex(modified),
                    "written DLL hashes are read back and validated.");
                Check(modified.Length == original.Length &&
                      modified[0x220] == 0xAA && modified[0x221] == 0xBB &&
                      modified[0x222] == 0xCC && modified[0x223] == 0xDD,
                    "only explicit expected bytes are replaced.");
                var report = saved.PublicMetadata().AsComment();
                Check(report.StartsWith("termsrv-offline/v1\n", StringComparison.Ordinal) &&
                      report.Contains("architecture=" + layout.Architecture + "\n") &&
                      report.Contains("original_crc32=" + preview.OriginalCrc32 + "\n") &&
                      report.Contains("patched_crc32=" + saved.FinalCrc32 + "\n") &&
                      report.Contains("original_sha256=" + preview.OriginalSha256 + "\n") &&
                      !report.Contains(directory, StringComparison.OrdinalIgnoreCase),
                    "public report includes architecture, CRC, SHA without filesystem paths.");

                Refuses<IOException>(() => OfflineDllPatcher.SavePatched(preview, output),
                    "existing output is never overwritten.");
                Refuses<InvalidOperationException>(() => OfflineDllPatcher.SavePatched(preview, input),
                    "source DLL cannot be overwritten.");
                Refuses<InvalidOperationException>(() => OfflineDllPatcher.SavePatched(preview,
                    Path.Combine(root, "termsrv.dll")), "output must have a distinct name.");
                var altered = (byte[])original.Clone();
                altered[0x220] ^= 0x01;
                File.WriteAllBytes(input, altered);
                Refuses<InvalidOperationException>(() =>
                    OfflineDllPatcher.SavePatched(preview, Path.Combine(directory, "stale.patched.dll")),
                    "a changed source file invalidates stale preview.");
                File.WriteAllBytes(input, original);

                var duplicate = (byte[])original.Clone();
                new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(duplicate, 0x250);
                File.WriteAllBytes(input, duplicate);
                Check(OfflineDllPatcher.Inspect(input, "11 22 33 44", "AA BB CC DD")
                      .Plan.State == PatchState.Ambiguous,
                      "multiple matching signatures are never patched.");
                File.WriteAllBytes(input, original);

                var headerOnly = SyntheticDll(x64, match: 0x180);
                File.WriteAllBytes(input, headerOnly);
                Check(OfflineDllPatcher.Inspect(input, "11 22 33 44", "AA BB CC DD")
                      .Plan.State == PatchState.Unsupported,
                      "a signature in PE headers is rejected for both architectures.");
            }
            string invalidPath = Path.Combine(root, "junk.dll");
            File.WriteAllBytes(invalidPath, new byte[0x500]);
            Refuses<InvalidDataException>(() => OfflineDllPatcher.Inspect(invalidPath),
                "wrong source filename refused.");
            string namedJunk = Path.Combine(root, "termsrv.dll");
            File.WriteAllBytes(namedJunk, new byte[0x500]);
            Refuses<InvalidDataException>(() => OfflineDllPatcher.Inspect(namedJunk),
                "non-PE termsrv.dll rejected.");
            Console.WriteLine($"PASS: {checks} x86/x64 offline PE, patch-copy, CRC32/SHA-256, " +
                "stale, duplicate, unsafe region, overwrite and opt-in report checks.");
            Console.WriteLine("LIMIT: no Windows system DLL or RDP services modified.");
            return checks;
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }
}
