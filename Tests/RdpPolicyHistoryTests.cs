using System.IO;
using TermsrvPatcherUnified.Core;

internal static class RdpPolicyHistoryTests
{
    private static int count;
    private static void Verify(bool ok, string reason)
    {
        count++;
        if (!ok) throw new InvalidOperationException("RDP policy/history QA failed: " + reason);
    }

    internal static int Run()
    {
        var conflict = RdpPolicyDiagnostics.Evaluate("NLA", 0, 1, 0, 1);
        Verify(conflict.Assessment == "Policy differs", "different local and policy values reported");
        Verify(conflict.Explanation.Contains("override"), "conflicts explain possible precedence");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", 1, 1, 0, 1).Assessment ==
            "Policy configured", "equal settings still display policy presence");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", 1, null, 0, 1).Assessment ==
            "Local setting", "missing policy is not a conflict");
        Verify(RdpPolicyDiagnostics.Evaluate("NLA", null, null, 0, 1).Assessment ==
            "Unavailable", "missing values do not imply safe defaults");
        Verify(RdpPolicyDiagnostics.Evaluate("Port", 70000, null, 1, 65535).Assessment ==
            "Invalid value", "out-of-range values are rejected");
        Verify(RdpPolicyDiagnostics.Evaluate("Port", 3389, null, 1, 65535).Assessment ==
            "Local setting", "valid TCP port accepted");
        Verify(RdpPolicyDiagnostics.Evaluate("Security", 0, 2, 0, 2).Assessment ==
            "Policy differs", "security-layer conflicts detected");
        var unchanged = new RdpStatus(true, true, true);
        var modified = new RdpStatus(true, false, false);
        var followUp = RdpPostApply.Build(unchanged, modified, synchronizeFirewall: false);
        Verify(followUp.ConnectionRetest &&
               followUp.Rows.Count == 4 &&
               followUp.Rows.Single(x => x.Setting == "Network Level Authentication")
                   .Status == "Local value changed" &&
               followUp.Rows.Single(x => x.Setting == "One session per user")
                   .RequiredAction.Contains("next user sign-in", StringComparison.OrdinalIgnoreCase),
               "RDP follow-up identifies NLA and session changes without requiring automatic service restart");
        var stable = RdpPostApply.Build(unchanged, unchanged, synchronizeFirewall: false);
        Verify(!stable.ConnectionRetest && stable.Rows.All(x => x.Status != "Local value changed"),
               "unchanged RDP preferences do not invent pending restart requirements");
        Verify(RdpPostApply.InterpretPort(3389) == 3389 &&
               RdpPostApply.InterpretPort(65535) == 65535 &&
               RdpPostApply.InterpretPort(0) is null &&
               RdpPostApply.InterpretPort(65536) is null &&
               RdpPostApply.InterpretPort("3389") is null,
               "port reader treats invalid and non-numeric values as unknown");
        Verify(RdpPostApply.ListenerRestartRequired(3389, 3390) &&
               !RdpPostApply.ListenerRestartRequired(3389, 3389) &&
               !RdpPostApply.ListenerRestartRequired(null, 3389) &&
               !RdpPostApply.ListenerRestartRequired(3389, null),
               "restart review is enabled only by an observed valid listener-port change");
        Verify(RdpBlankPasswordSecurity.Interpret(1) == true &&
               RdpBlankPasswordSecurity.Interpret(0) == false &&
               RdpBlankPasswordSecurity.Interpret(2) is null &&
               RdpBlankPasswordSecurity.Interpret("1") is null &&
               RdpBlankPasswordSecurity.Interpret(null) is null,
               "blank-password policy treats malformed/missing values as unknown");
        var allowedPort = RdpLocalAdvancedSettings.Find("RDP TCP port");
        Verify(allowedPort is not null && allowedPort.RegistryValue == "PortNumber" &&
               RdpLocalAdvancedSettings.Find("Disable clipboard redirection") is null &&
               RdpPolicySourceResolver.ValueForSetting("Disable clipboard redirection") == "fDisableClip",
               "editable registry names remain allowlisted separately from read-only RSoP source lookup");
        Verify(RdpPolicySourceResolver.ValueForSetting("Disable camera redirection") == "fDisableCameraRedir" &&
               RdpPolicySourceResolver.ValueForSetting("Disable microphone redirection") == "fDisableAudioCapture" &&
               RdpPolicySourceResolver.ValueForSetting("Disable LPT port redirection") == "fDisableLPT" &&
               RdpPolicySourceResolver.ValueForSetting("Disable Plug and Play device redirection") == "fDisablePNPRedir" &&
               RdpPolicySourceResolver.ValueForSetting("Allow time-zone redirection") == "fEnableTimeZoneRedirection" &&
               RdpPolicySourceResolver.ValueForSetting("Automatic reconnection") == "fDisableAutoReconnect" &&
               RdpPolicySourceResolver.ValueForSetting("RDP keep-alive interval") == "KeepAliveInterval" &&
               RdpLocalAdvancedSettings.Find("Disable camera redirection") is null &&
               RdpLocalAdvancedSettings.Find("RDP keep-alive interval") is null,
               "verified ADMX value names are diagnostic-only, not additional local writers");
        Verify(RdpPolicyDiagnostics.DescribeBlankPasswordPolicy(true).LocalValue.StartsWith("1", StringComparison.Ordinal) &&
               RdpPolicyDiagnostics.DescribeBlankPasswordPolicy(false).LocalValue.StartsWith("0", StringComparison.Ordinal) &&
               RdpPolicyDiagnostics.DescribeBlankPasswordPolicy(null).Assessment == "Windows LSA security",
               "blank-password explanations distinguish both LSA DWORD values and unknown source");

        Verify(RdpLocalAdvancedSettings.ParseValue(allowedPort!, "3389") == 3389 &&
               RdpLocalAdvancedSettings.ParseValue(allowedPort, "65535") == 65535,
               "numeric port editor accepts exact valid values");
        bool refusedPort = false;
        try { RdpLocalAdvancedSettings.ParseValue(allowedPort!, "65536"); }
        catch (ArgumentOutOfRangeException) { refusedPort = true; }
        Verify(refusedPort, "out-of-range RDP editor values are blocked");

        const string gpoGuid = "{11111111-2222-3333-4444-555555555555}";
        string gpoId = "CN=" + gpoGuid +
            ",CN=Policies,CN=System,DC=yosh,DC=ac,DC=il";
        var registryRule = new RdpRsopRegistryEntry(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            "PortNumber", gpoId, 1);
        var winning = RdpPolicySourceResolver.Resolve("PortNumber",
            new[] { registryRule },
            new[] { new RdpRsopGpoEntry(gpoId, gpoGuid, "Domain RDP Security Settings") });
        Verify(winning.Resolved && winning.Label == "Domain RDP Security Settings" &&
               winning.Details.Contains("PortNumber", StringComparison.Ordinal) &&
               winning.Details.Contains(gpoGuid, StringComparison.OrdinalIgnoreCase),
               "blocked RDP option displays exact winning domain GPO plus registry value");
        var lost = RdpPolicySourceResolver.Resolve("PortNumber",
            new[] { registryRule with { Precedence = 2 } },
            new[] { new RdpRsopGpoEntry(gpoId, gpoGuid, "Losing policy") });
        Verify(!lost.Resolved && lost.Label == "GPO not identified",
               "non-winning precedence must never be shown as blocking GPO");
        var mismatchedPath = RdpPolicySourceResolver.Resolve("PortNumber",
            new[] { registryRule with {
                RegistryKey = @"HKLM\SOFTWARE\Policies\Other\Terminal Services" } },
            new[] { new RdpRsopGpoEntry(gpoId, gpoGuid, "Unrelated policy") });
        Verify(!mismatchedPath.Resolved, "policy key must match exactly, not a suffix or name");
        var mismatchedGpo = RdpPolicySourceResolver.Resolve("PortNumber",
            new[] { registryRule },
            new[] { new RdpRsopGpoEntry("CN={AAAAAAA1-2222-3333-4444-555555555555}",
                "{AAAAAAA1-2222-3333-4444-555555555555}", "Other GPO") });
        Verify(!mismatchedGpo.Resolved && mismatchedGpo.Details.Contains(gpoGuid,
                    StringComparison.OrdinalIgnoreCase),
               "unmatched RSoP GPO GUID is shown only as an unresolved identifier");
        Verify(RdpPolicySourceResolver.NormalizeRegistryKey(
               @"\Registry\Machine\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")
                .Equals(RdpPolicySourceResolver.NormalizeRegistryKey(
               @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"),
               StringComparison.OrdinalIgnoreCase),
               "RSoP key aliases map to the same exact computer policy key");
        bool refusedUnknownPolicy = false;
        try { RdpPolicySourceResolver.Resolve("UntrustedValue", Array.Empty<RdpRsopRegistryEntry>(),
            Array.Empty<RdpRsopGpoEntry>()); }
        catch (ArgumentException) { refusedUnknownPolicy = true; }
        Verify(refusedUnknownPolicy, "arbitrary registry values cannot be treated as editable RDP policies");

        Verify(RdpPolicyDiagnostics.Evaluate("Idle limit", null, 300000, 0, int.MaxValue)
                   .Assessment == "Policy configured",
               "session time-limit policy is inspected without assuming local defaults");
        Verify(RdpPolicyDiagnostics.Evaluate("Clipboard", null, null, 0, 1)
                   .Assessment == "Unavailable",
               "absent redirection policy is not mistaken for allowing redirection");

        Verify(!AutoReapplyScheduler.NeedsInspection("abcdef", UpdateIntegration.Version,
                    "abcdef", UpdateIntegration.Version),
               "unchanged DLL with same automatic pattern database is not retried");
        Verify(AutoReapplyScheduler.NeedsInspection("abcdef", UpdateIntegration.Version,
                    "123456", UpdateIntegration.Version),
               "changed DLL triggers a fresh exact-signature inspection");
        Verify(AutoReapplyScheduler.NeedsInspection("abcdef", UpdateIntegration.Version,
                    "abcdef", "0.0.0"),
               "new application build can recheck previously unsupported DLLs");
        Verify(AutoReapplyScheduler.HasProtectedTaskDacl(
                    "D:P(A;;GA;;;SY)(A;;GA;;;BA)"),
               "SYSTEM/Administrators-only task DACL accepted");
        Verify(!AutoReapplyScheduler.HasProtectedTaskDacl(
                    "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;BU)") &&
               !AutoReapplyScheduler.HasProtectedTaskDacl(
                    "D:AI(A;;GA;;;SY)(A;;GA;;;BA)") &&
               !AutoReapplyScheduler.HasProtectedTaskDacl(null),
               "user-writable or inherited task DACL fails closed");
        Verify(AutoReapplyScheduler.TaskName == "TermsrvPatcherUnified-AutoReapply" &&
               AutoReapplyScheduler.WorkerPath.StartsWith(
                   Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                   StringComparison.OrdinalIgnoreCase),
               "automatic task worker lives in machine-owned ProgramData, not Desktop");

        var root = Path.Combine(Path.GetTempPath(), "Termsrv-History-QA-" + Guid.NewGuid().ToString("N"));
        var file = Path.Combine(root, "events.jsonl");
        try
        {
            Verify(OperationHistory.ReadRecent(50, file).Entries.Count == 0 && !Directory.Exists(root),
                "viewing missing history does not create directories");
            Verify(!OperationHistory.TryRecord("Unknown", "Success", file: file),
                "unknown event categories refused");
            Verify(OperationHistory.TryRecord("Apply", "Success", "10.0.26100.1000",
                new string('a', 64), new string('b', 64), file: file),
                "bounded metadata appended to temporary history");
            Verify(OperationHistory.TryRecord("Restore", "Failure",
                failureType: "IOException", file: file), "failure type stored without message");
            Verify(OperationHistory.TryRecord("RdpSettings", "Success", file: file),
                "RDP setting event appended");
            var saved = OperationHistory.ReadRecent(2, file);
            Verify(saved.Entries.Count == 2 && saved.Entries[0].Operation == "RdpSettings" &&
                saved.Entries[1].Operation == "Restore",
                "latest entries returned in reverse chronological order");
            Verify(saved.Entries.All(e => e.IsValid()), "read validates schema and fields");
            Verify(!File.ReadAllText(file).Contains(root, StringComparison.OrdinalIgnoreCase) &&
                !File.ReadAllText(file).Contains("username", StringComparison.OrdinalIgnoreCase),
                "history contains no paths or account identities");
            File.AppendAllText(file, "{malformed" + Environment.NewLine);
            var corrupted = OperationHistory.ReadRecent(4, file);
            Verify(corrupted.InvalidEntries == 1 && corrupted.Entries.Count == 3,
                "malformed JSON ignored without losing verified entries");
            var validLine = File.ReadLines(file).First();
            var nullVersionLine = validLine.Replace(
                "\"AppVersion\":\"" + UpdateIntegration.Version + "\"",
                "\"AppVersion\":null", StringComparison.Ordinal);
            Verify(nullVersionLine != validLine, "test fixture contains an application version");
            File.AppendAllText(file, nullVersionLine + Environment.NewLine);
            var invalidFields = OperationHistory.ReadRecent(5, file);
            Verify(invalidFields.InvalidEntries == 2 && invalidFields.Entries.Count == 3,
                "JSON with null required fields is rejected without crashing the history view");
            Verify(!OperationHistory.TryRecord("Apply", "Unknown", file: file),
                "invalid outcome refused");
            Verify(OperationHistory.IsSha(new string('0', 64)) &&
                !OperationHistory.IsSha(new string('g', 64)), "SHA validation is exact");
            Verify(OperationHistory.IsDllVersion("10.0.26100.1000") &&
                !OperationHistory.IsDllVersion("../../user"), "DLL version sanitized");
            if (OperatingSystem.IsWindows())
            {
                var report = RdpPolicyDiagnostics.ReadLocal();
                Verify(report.Values.Count >= 17 && report.AsText().Contains("READ ONLY"),
                    "Windows registry/service including extended RDP policy report");
                Verify(report.Values.Any(x => x.Setting == "Blank-password restriction (local accounts)") &&
                       report.Values.Any(x => x.Setting == "Idle session limit") &&
                       report.Values.Any(x => x.Setting == "Disable clipboard redirection"),
                    "advanced RDP categories present in read-only inventory");
                Verify(!report.AsText().Contains(Environment.UserName, StringComparison.OrdinalIgnoreCase),
                    "diagnostics never include local account name");
            }
            Console.WriteLine("PASS: " + count +
                " RDP policy and local operation history tests; no registry/service/DLL writes.");
            return count;
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
