using System.Buffers.Binary;
using System.IO;
using TermsrvPatcherUnified.Core;

internal static class RdpHealthTests
{
    private static int count;
    private static void Verify(bool value, string reason)
    {
        count++;
        if (!value) throw new Exception("RDP Health QA failed: " + reason);
    }

    private static byte[] FakePeDll()
    {
        var data = new byte[0x600];
        data[0] = (byte)'M'; data[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C, 4), 0x80);
        new byte[] { (byte)'P', (byte)'E', 0, 0 }.CopyTo(data, 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x84, 2), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x86, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x94, 2), 0xF0);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x96, 2), 0x2000);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x98, 2), 0x20B);
        int section = 0x80 + 24 + 0xF0;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 16, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 20, 4), 0x200);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(section + 36, 4), 0x60000020);
        return data;
    }

    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "Termsrv-Health-QA-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var dll = Path.Combine(root, "termsrv.dll");
            var baseline = Path.Combine(root, "state", "baseline.json");
            var original = FakePeDll();
            File.WriteAllBytes(dll, original);
            var first = DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline);
            Verify(first.Status == DllDriftStatus.NoBaseline, "first check finds no baseline");
            Verify(!Directory.Exists(Path.GetDirectoryName(baseline)!),
                "read-only health check never creates directories");
            Verify(first.AsText().Contains("READ ONLY") &&
                   !first.AsText().Contains(root, StringComparison.OrdinalIgnoreCase),
                "publicly copyable health text has no local filesystem path");
            var saved = DllHealthMonitor.RecordBaseline(dll, "10.0.26100.1000", baseline);
            Verify(saved.Status == DllDriftStatus.Unchanged && File.Exists(baseline),
                "user-approved baseline is written to user-specified metadata file");
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline).Status ==
                   DllDriftStatus.Unchanged, "same version and SHA-256 are unchanged");
            var changed = (byte[])original.Clone();
            changed[0x220] = 0x83;
            File.WriteAllBytes(dll, changed);
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline).Status ==
                   DllDriftStatus.BytesChanged, "same-version changed bytes detected");
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.2000", baseline).Status ==
                   DllDriftStatus.FileVersionChanged, "new version identified separately");
            Verify(File.ReadAllBytes(dll).SequenceEqual(changed),
                "health checks never write or repair the DLL");
            File.WriteAllBytes(baseline, new byte[] { 0x7B, 0xFF, 0x7D });
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline).Status ==
                   DllDriftStatus.InvalidBaseline, "corrupt baseline is not trusted");
            File.WriteAllText(baseline, new string('a', 4096));
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline).Status ==
                   DllDriftStatus.InvalidBaseline, "oversized baseline is rejected");
            Verify(DllHealthMonitor.RecordBaseline(dll, "10.0.26100.1000", baseline)
                   .Status == DllDriftStatus.Unchanged, "operator can reset baseline explicitly");
            Verify(DllHealthMonitor.CheckFile(dll, "10.0.26100.1000", baseline).Status ==
                   DllDriftStatus.Unchanged, "new baseline matches currently observed DLL");
            Verify(RdpSessionViewer.StateName(0) == "Active" &&
                   RdpSessionViewer.StateName(4) == "Disconnected" &&
                   RdpSessionViewer.StateName(300).StartsWith("Unknown", StringComparison.Ordinal),
                   "all WTS session states are rendered deterministically");
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    var sessions = RdpSessionViewer.ReadLocal();
                    Verify(sessions.Count <= 4096 &&
                           sessions.All(s => s.SessionId >= 0 && s.State.Length > 0),
                        "native WTS enumerator returns bounded read-only session identities");
                    Console.WriteLine("PASS: native Windows WTS enumeration (session identifiers not logged).");
                }
                catch (System.ComponentModel.Win32Exception e)
                {
                    // Some headless test runners restrict the WTS service. Keep
                    // this explicit rather than falsely claiming a real WTS PASS.
                    Console.WriteLine("SKIP: native WTS access unavailable on this runner: Win32 " +
                        e.NativeErrorCode);
                }
            }
            Console.WriteLine($"PASS: {count} passive DLL health and WTS state tests; " +
                              "no system DLL patch, logoff, service stop or network call.");
            return count;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
