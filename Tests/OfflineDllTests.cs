using System.Buffers.Binary;
using TermsrvPatcherUnified.Core;

/// <summary>
/// Completely disposable PE32 and PE32+ DLL-copy regression; system DLL and
/// TermService are never opened for modification.
/// </summary>
internal static class OfflineDllTests
{
    internal static int Run()
    {
        var dir = Path.Combine(Path.GetTempPath(),
            "Termsrv-Offline-QA-" + Guid.NewGuid().ToString("N"));
        int checks = 0;
        void Check(bool ok, string why)
        {
            checks++;
            if (!ok) throw new Exception("Offline DLL test failed: " + why);
        }
        void Refuse<T>(Action action, string why) where T : Exception
        {
            bool rejected = false;
            try { action(); }
            catch (T) { rejected = true; }
            Check(rejected, why);
        }
        try
        {
            Directory.CreateDirectory(dir);
            Check(OfflineDllPatcher.Crc32Hex(System.Text.Encoding.ASCII.GetBytes("123456789"))
                == "CBF43926", "CRC32 standard test vector");
            var profiles = PatchCatalog.LoadAutomatic();
            var autoPattern = profiles[0].Groups.Single();
            var x64 = Path.Combine(dir, "x64");
            var x86 = Path.Combine(dir, "x86");
            Directory.CreateDirectory(x64);
            Directory.CreateDirectory(x86);
            var x64Source = Path.Combine(x64, "termsrv.dll");
            var x86Source = Path.Combine(x86, "termsrv.dll");
            var bytes64 = MakeDll("x64");
            for (int i = 0; i < autoPattern.Search.Length; i++)
                bytes64[0x220 + i] = autoPattern.Search[i] ?? (byte)0x73;
            File.WriteAllBytes(x64Source, bytes64);
            var bytes86 = MakeDll("x86");
            new byte[] { 0x11, 0x22, 0x33, 0x44 }.CopyTo(bytes86, 0x220);
            File.WriteAllBytes(x86Source, bytes86);
            Check(PeSafety.ReadOfflineDllSections(bytes64).Architecture == "x64",
                "correct x64 detection");
            Check(PeSafety.ReadOfflineDllSections(bytes86).Architecture == "x86",
                "correct x86 detection");
            Refuse<InvalidDataException>(() => PeSafety.ReadAmd64DllSections(bytes86),
                "existing protected DLL validation must remain x64-only");

            var planned64 = OfflineDllPatcher.Inspect(x64Source);
            Check(planned64.Architecture == "x64" &&
                  planned64.Plan.State == PatchState.Ready, "automatic x64 exact match");
            Check(planned64.OriginalSha256 == SystemInfo.Sha256(bytes64) &&
                  planned64.OriginalCrc32 == OfflineDllPatcher.Crc32Hex(bytes64),
                "original x64 hashes verified");
            var output64 = Path.Combine(x64, "termsrv.patched.dll");
            var created64 = OfflineDllPatcher.SavePatched(planned64, output64);
            Check(File.Exists(output64) &&
                  created64.FinalSha256 == SystemInfo.Sha256(File.ReadAllBytes(output64)),
                "x64 saved copy hash verified");
            Check(File.ReadAllBytes(x64Source).SequenceEqual(bytes64),
                "x64 source remains byte-identical");
            Check(!created64.FinalSha256.Equals(planned64.OriginalSha256,
                StringComparison.OrdinalIgnoreCase), "x64 expected patch changes file");
            Check(created64.FinalCrc32 == OfflineDllPatcher.Crc32Hex(
                File.ReadAllBytes(output64)), "output CRC32 independently checked");
            Refuse<IOException>(() => OfflineDllPatcher.SavePatched(planned64, output64),
                "existing output not overwritten");
            Refuse<InvalidOperationException>(() =>
                OfflineDllPatcher.SavePatched(planned64, x64Source),
                "original DLL cannot be overwritten");
            Refuse<InvalidOperationException>(() =>
                OfflineDllPatcher.SavePatched(planned64, Path.Combine(x86, "termsrv.dll")),
                "an output named termsrv.dll is refused");

            var unsupported86 = OfflineDllPatcher.Inspect(x86Source);
            Check(unsupported86.Architecture == "x86" &&
                  unsupported86.Plan.State is PatchState.Unknown or PatchState.Unsupported,
                "no x64 signatures are applied to x86 DLL automatically");
            Refuse<InvalidOperationException>(() =>
                OfflineDllPatcher.SavePatched(unsupported86,
                    Path.Combine(x86, "termsrv.patched.dll")),
                "x86 unknown signature never produces a patched file");
            var planned86 = OfflineDllPatcher.Inspect(x86Source,
                "11 22 33 44", "AA BB CC DD");
            Check(planned86.Plan.State == PatchState.Ready &&
                  planned86.Architecture == "x86", "manual x86 verified match");
            var created86 = OfflineDllPatcher.SavePatched(planned86,
                Path.Combine(x86, "termsrv.patched.dll"));
            Check(File.ReadAllBytes(x86Source).SequenceEqual(bytes86),
                "x86 source remains intact");
            Check(created86.FinalSha256 == SystemInfo.Sha256(
                File.ReadAllBytes(created86.OutputPath)), "x86 output SHA-256 checked");
            Check(created86.FinalCrc32 == OfflineDllPatcher.Crc32Hex(
                File.ReadAllBytes(created86.OutputPath)), "x86 output CRC32 checked");
            Refuse<FormatException>(() => OfflineDllPatcher.Inspect(
                x86Source, "11 22 33 44", null),
                "incomplete manual pattern is refused");
            File.WriteAllBytes(x86Source, bytes86.Concat(new byte[] { 0x00 }).ToArray());
            Refuse<InvalidOperationException>(() => OfflineDllPatcher.SavePatched(planned86,
                Path.Combine(x86, "another.patched.dll")),
                "source changed after preview blocks offline output");

            var notDll = Path.Combine(dir, "ordinary.dll");
            File.WriteAllBytes(notDll, bytes64);
            Refuse<InvalidDataException>(() => OfflineDllPatcher.Inspect(notDll),
                "non-termsrv DLL input rejected");
            Check(!Directory.EnumerateFiles(dir, "*.tmp", SearchOption.AllDirectories).Any(),
                "no temporary output left behind");
            Console.WriteLine($"PASS: {checks} offline x86/x64 PE, CRC32/SHA-256, " +
                              "copy safety and stale-preview regression assertions.");
            return checks;
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    private static byte[] MakeDll(string arch)
    {
        var bytes = Enumerable.Repeat((byte)0xFA, 0x600).ToArray();
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0x3C, 4), 0x80);
        new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(bytes, 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x84, 2),
            arch == "x64" ? (ushort)0x8664 : (ushort)0x14c);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x86, 2), 1);
        ushort optionalSize = arch == "x64" ? (ushort)0xF0 : (ushort)0xE0;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x94, 2), optionalSize);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x96, 2), 0x2000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x98, 2),
            arch == "x64" ? (ushort)0x20B : (ushort)0x10B);
        int at = 0x80 + 24 + optionalSize;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 20, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at + 36, 4), 0x60000020);
        return bytes;
    }
}
