using System.Text.Json;
using System.Text.Json.Serialization;

namespace TermsrvPatcherUnified.Core;

internal sealed record DryRunByteChange(int Offset, int Length, string BeforeHex, string AfterHex);

/// <summary>
/// Deterministic, read-only preview. It cannot execute, create a backup,
/// control a service, or authorize a protected DLL write.
/// </summary>
internal sealed record PatchDryRun(
    string Schema,
    string SourceFile,
    string HostWindows,
    int HostBuild,
    int HostUbr,
    string DllFileVersion,
    string Mode,
    string State,
    string Profile,
    string SourceSha256,
    string? PredictedSha256,
    bool CreatePersistentBackup,
    bool CanApplyAfterSeparateApproval,
    string Explanation,
    IReadOnlyList<DryRunByteChange> Changes)
{
    private static readonly JsonSerializerOptions JsonSettings = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    internal static PatchDryRun Build(PatchPlan plan, WindowsDetails host,
        bool createBackup)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(host);
        // Re-read after checking the plan: a pending Windows Update, parallel
        // process, or replaced file invalidates a stale exported preview.
        var current = File.ReadAllBytes(plan.FilePath);
        var verifiedSourceSha = SystemInfo.Sha256(current);
        if (!verifiedSourceSha.Equals(plan.OriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "The inspected DLL changed. Run Check again before exporting a DryRun.");

        var edits = new List<DryRunByteChange>();
        string? predicted = null;
        bool isReady = plan.State == PatchState.Ready &&
                       plan.PatchedBytes is not null &&
                       plan.Edits.Count is > 0 and <= 16;
        if (isReady)
        {
            PeSafety.RequireExecutableEdits(current, plan.Edits);
            var rebuilt = (byte[])current.Clone();
            int lastEnd = 0;
            foreach (var edit in plan.Edits.OrderBy(e => e.Offset))
            {
                if (edit.Offset < lastEnd || edit.Expected.Length is < 1 or > 64 ||
                    edit.Offset < 0 || edit.Offset > current.Length - edit.Expected.Length ||
                    edit.Expected.Length != edit.Replacement.Length ||
                    !current.AsSpan(edit.Offset, edit.Expected.Length).SequenceEqual(edit.Expected))
                    throw new InvalidDataException("DryRun contains an invalid or overlapping change.");
                edit.Replacement.CopyTo(rebuilt, edit.Offset);
                edits.Add(new DryRunByteChange(edit.Offset, edit.Expected.Length,
                    Convert.ToHexString(edit.Expected), Convert.ToHexString(edit.Replacement)));
                lastEnd = checked(edit.Offset + edit.Expected.Length);
            }
            if (!rebuilt.SequenceEqual(plan.PatchedBytes))
                throw new InvalidDataException("DryRun candidate differs from verified preview.");
            predicted = SystemInfo.Sha256(rebuilt);
            if (predicted.Equals(verifiedSourceSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("DryRun preview would not change the DLL.");
        }

        return new PatchDryRun(
            "termsrv-dry-run/v1",
            Path.GetFileName(plan.FilePath),  // never include an absolute path
            host.Name, host.Build, host.Ubr,
            plan.FileVersion,
            plan.IsManual ? "manual" : "automatic",
            plan.State.ToString(),
            plan.ProfileId.Length > 160 ? plan.ProfileId[..160] : plan.ProfileId,
            verifiedSourceSha,
            predicted,
            createBackup,
            isReady,
            plan.Description,
            edits);
    }

    internal string ToJson() => JsonSerializer.Serialize(this, JsonSettings) + "\n";

    internal void SaveNew(string outputPath, string sourcePath)
    {
        var full = Path.GetFullPath(outputPath);
        if (!Path.GetExtension(full).Equals(".json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("DryRun reports must use the .json extension.");
        if (full.Equals(Path.GetFullPath(sourcePath), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Refusing to overwrite the inspected DLL.");
        // CreateNew never overwrites a pre-existing file, including a backup or
        // another operator's report. Only the explicitly chosen output is written.
        using var stream = new FileStream(full, FileMode.CreateNew,
            FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false));
        writer.Write(ToJson());
    }
}
