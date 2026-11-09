using System.Diagnostics;

namespace TermsrvPatcherUnified.Core;

public sealed class TermsrvEngine : IDisposable
{
    private readonly Action<string>? notice;
    public TermsrvEngine(Action<string>? notice) { this.notice = notice; }

    public WindowsDetails EnvironmentInfo() => SystemInfo.Read();

    public PatchPlan Inspect()
    {
        var os = SystemInfo.Read();
        return InspectPath(os.DllPath, PatchCatalog.LoadAutomatic(), os.Supported,
            selectionContext: new AutomaticSelectionContext(os.Name, os.DisplayVersion, os.InstallationType));
    }

    public PatchPlan InspectManual(string find, string replace)
    {
        var os = SystemInfo.Read();
        var manual = PatchCatalog.Manual(find, replace);
        return InspectPath(os.DllPath, [manual], os.Supported, manualMode: true);
    }

    public PatchPlan InspectImported(string patchFile, int selectedRule)
    {
        var os = SystemInfo.Read();
        var patterns = PatchCatalog.Parse(File.ReadAllText(patchFile), "Imported manual file");
        if (selectedRule < 0 || selectedRule >= patterns.Count) throw new ArgumentOutOfRangeException(nameof(selectedRule));
        return InspectPath(os.DllPath, [patterns[selectedRule]], os.Supported, manualMode: true);
    }

    public PatchPlan InspectOffline(string file)
        => InspectPath(file, PatchCatalog.LoadAutomatic(), true);

    private static PatchPlan InspectPath(string path, IReadOnlyList<PatchProfile> profiles,
        bool supported, bool manualMode = false, AutomaticSelectionContext? selectionContext = null)
    {
        var bytes = File.ReadAllBytes(path);
        var preview = PatchCatalog.Inspect(bytes, path,
            FileVersionInfo.GetVersionInfo(path).FileVersion ?? "Unknown",
            SystemInfo.Sha256(bytes), supported, profiles, "x64", manualMode,
            selectionContext);
        // A byte match in .rsrc, file overlay or a damaged/non-DLL file is not
        // a valid Ready preview. Refuse it before displaying an Apply button.
        if (preview.State == PatchState.Ready)
        {
            try { PeSafety.RequireExecutableEdits(bytes, preview.Edits); }
            catch (InvalidDataException ex)
            {
                return preview with
                {
                    State = PatchState.Unsupported,
                    Description = "Signature matched, but PE safety validation rejected it: " + ex.Message,
                    Edits = [],
                    PatchedBytes = null
                };
            }
        }
        return preview;
    }

    public ScanReport ScanDll(string path, string? optionalSignature) => DllScanner.Scan(path, optionalSignature);

    public IReadOnlyList<string> BackupsForCurrentVersion()
    {
        var os = SystemInfo.Read();
        if (!File.Exists(os.DllPath) || !Directory.Exists(BackupDirectory)) return [];
        try { DllBackupStore.RequireTrustedLocation(BackupDirectory, create: false); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Message("Backup directory is not trusted; Restore choices hidden: " + ex.GetType().Name);
            return [];
        }
        return DllBackupStore.ListVerified(BackupDirectory, os.DllVersion,
            new FileInfo(os.DllPath).Length);
    }

    // Security boundary: AuditLog.Root is user-accessible by design and may
    // inherit normal ProgramData write permissions. Do NOT use it as the
    // parent of restorable system-DLL backups.
    // RequireTrustedLocation creates both directories with a protected DACL
    // for Administrators and SYSTEM only, or rejects pre-planted ACLs.
    // Existing backups in the legacy log folder are NEVER silently trusted
    // or imported from a potentially user-writable location.
    public static string BackupDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TermsrvPatcherUnified.Secure",
        "Backups");

    internal static string LegacyBackupDirectory => Path.Combine(AuditLog.Root, "Backups");

    private void Message(string line)
    {
        notice?.Invoke(line);
        AuditLog.Append(line);
    }

    public void Apply(PatchPlan preview, bool createBackup = true)
    {
        EnsureAllowed(preview.FilePath);
        using var operation = OperationLock.Acquire();
        if (operation.WasAbandoned)
            Message("Previous operation lock was abandoned. Rechecking the installed DLL before any change.");
        if (preview.State != PatchState.Ready || preview.PatchedBytes is null)
            throw new InvalidOperationException("Only a verified Ready preview may be applied.");
        var current = File.ReadAllBytes(preview.FilePath);
        if (!SystemInfo.Sha256(current).Equals(preview.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("termsrv.dll changed since preview. Run Check again.");
        if (current.Length != preview.PatchedBytes.Length)
            throw new InvalidOperationException("Replacement changes DLL length. Operation blocked.");
        // Check that the preview has no edits outside its declared regions.
        var independentlyRebuilt = (byte[])current.Clone();
        foreach (var edit in preview.Edits)
        {
            if (edit.Offset < 0 || edit.Offset + edit.Expected.Length > current.Length ||
                edit.Expected.Length != edit.Replacement.Length ||
                !current.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                throw new InvalidOperationException("Preview edit does not match current file.");
            edit.Replacement.CopyTo(independentlyRebuilt, edit.Offset);
        }
        if (!independentlyRebuilt.SequenceEqual(preview.PatchedBytes))
            throw new InvalidOperationException("Preview integrity check failed.");
        // A matching byte sequence in a resource/overlay is not a valid code patch.
        PeSafety.RequireExecutableEdits(current, preview.Edits);
        if (createBackup)
            DllBackupStore.RequireTrustedLocation(BackupDirectory, create: true);
        var saved = DllBackupStore.Save(BackupDirectory, preview.FileVersion, current,
            preview.OriginalSha256, createBackup);
        if (saved is not null)
            Message("Verified backup available: " + Path.GetFileName(saved));
        else
            Message("Permanent backup disabled for this Apply. In-operation rollback is still enabled.");
        WriteTransactional(preview.FilePath, preview.OriginalSha256, current, preview.PatchedBytes);
        OperationHistory.TryRecord("Apply", "Success", preview.FileVersion,
            preview.OriginalSha256, SystemInfo.Sha256(preview.PatchedBytes));
        Message($"Applied {(preview.IsManual ? "manual" : "automatic")} profile: {preview.ProfileId}");
    }

    public void Restore(string backupFile)
    {
        var os = SystemInfo.Read();
        EnsureAllowed(os.DllPath);
        using var operation = OperationLock.Acquire();
        if (operation.WasAbandoned)
            Message("Previous operation lock was abandoned. Revalidating backup and installed DLL.");
        DllBackupStore.RequireTrustedLocation(BackupDirectory, create: false);
        var current = File.ReadAllBytes(os.DllPath);
        PeSafety.ReadAmd64DllSections(current);
        var desired = DllBackupStore.ReadVerified(BackupDirectory, backupFile,
            os.DllVersion, current.LongLength);
        // A modified/unknown DLL is restored only by explicit administrator action.
        WriteTransactional(os.DllPath, SystemInfo.Sha256(current), current, desired);
        OperationHistory.TryRecord("Restore", "Success", os.DllVersion,
            SystemInfo.Sha256(current), SystemInfo.Sha256(desired));
        Message($"Restored backup: {Path.GetFileName(backupFile)}");
    }

    private void WriteTransactional(string file, string expectedSha, byte[] before, byte[] after)
    {
        if (SystemInfo.Sha256(before) != expectedSha)
            throw new InvalidOperationException("Expected source checksum does not match.");
        // Validate the native bundle and secured extraction directory before any
        // RDP service is stopped. A missing/bad NSudo library must not disrupt RDP.
        NsudoDevilModeScope.Preflight();
        ServiceGuard? services = null;
        Exception? failure = null;
        try
        {
            services = new ServiceGuard();
            if (SystemInfo.Sha256(File.ReadAllBytes(file)) != expectedSha)
                throw new IOException("DLL was changed by Windows after checking. No changes made.");
            try
            {
                PrivilegeHelper.WriteProtected(file, after);
                if (SystemInfo.Sha256(File.ReadAllBytes(file)) != SystemInfo.Sha256(after))
                    throw new IOException("Verification of written DLL failed.");
            }
            catch (Exception originalError)
            {
                try
                {
                    if (SystemInfo.Sha256(File.ReadAllBytes(file)) != expectedSha)
                    {
                        PrivilegeHelper.WriteProtected(file, before);
                        if (SystemInfo.Sha256(File.ReadAllBytes(file)) != expectedSha)
                            throw new IOException("Rollback verification failed.");
                    }
                    Message("Attempted rollback to pre-operation bytes.");
                }
                catch (Exception rollbackError)
                {
                    Message("CRITICAL: rollback failed: " + rollbackError.Message);
                    throw new AggregateException("Write and rollback failed; use a verified local backup or VM snapshot to recover.",
                        originalError, rollbackError);
                }
                throw;
            }
        }
        catch (Exception ex) { failure = ex; }
        finally { services?.Dispose(); }
        if (services is not null && services.RestartFailures.Count > 0)
            throw new AggregateException("Remote Desktop service restart failed. Inspect operations.log.",
                (failure is null ? [] : new[] { failure }).Concat(services.RestartFailures));
        if (failure is not null) throw failure;
        Message("DLL write verified; original file ownership and ACL were not modified.");
    }

    private static void EnsureAllowed(string file)
    {
        var details = SystemInfo.Read();
        if (!details.Supported) throw new NotSupportedException("Only x64 Windows desktop is supported for applying.");
        if (!SystemInfo.IsAdministrator()) throw new UnauthorizedAccessException("Run as Administrator to apply/restore.");
        var actual = Path.GetFullPath(details.DllPath);
        if (!Path.GetFullPath(file).Equals(actual, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Modification is limited to the local system DLL.");
    }

    public void Dispose() { }
}
