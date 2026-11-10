using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TermsrvPatcherUnified.Core;

internal enum DllDriftStatus { NoBaseline, Unchanged, FileVersionChanged, BytesChanged, InvalidBaseline, FirstSeenUnverified }

/// <summary>
/// A user-approved, locally stored observation. This is not an authenticated
/// signature and must NEVER determine whether Apply or Restore is permitted.
/// </summary>
internal sealed record DllHealthSnapshot(
    string Schema, string DllVersion, string Sha256, long FileLength, DateTimeOffset ObservedUtc)
{
    internal const string SchemaId = "termsrv-dll-health/v1";
    private static readonly Regex ShaPattern = new(
        @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    internal void Validate()
    {
        if (Schema != SchemaId || string.IsNullOrWhiteSpace(DllVersion) ||
            DllVersion.Length > 160 || DllVersion.Any(c => char.IsControl(c)) ||
            !ShaPattern.IsMatch(Sha256 ?? "") ||
            FileLength is < 128 or > 52428800 ||
            ObservedUtc.Offset != TimeSpan.Zero ||
            ObservedUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
            ObservedUtc < new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero))
            throw new InvalidDataException("Invalid or untrusted local DLL health baseline.");
    }
}

internal sealed record DllHealthReport(
    DllHealthSnapshot Current, DllHealthSnapshot? Baseline,
    DllDriftStatus Status, string? Warning, DllHealthSnapshot? FirstSeen = null,
    string? FirstSeenWarning = null)
{
    internal string AsText()
    {
        var text = new StringBuilder()
            .AppendLine("Local DLL health — READ ONLY")
            .AppendLine("No system change, Windows service restart, scheduled task or network request.")
            .AppendLine()
            .AppendLine($"Current DLL version: {Current.DllVersion}")
            .AppendLine($"Current SHA-256: {Current.Sha256}")
            .AppendLine($"Current size: {Current.FileLength} bytes")
            .AppendLine($"Checked UTC: {Current.ObservedUtc:yyyy-MM-ddTHH:mm:ssZ}")
            .AppendLine();
        if (Baseline is not null)
        {
            text.AppendLine($"Recorded baseline version: {Baseline.DllVersion}")
                .AppendLine($"Recorded baseline SHA-256: {Baseline.Sha256}")
                .AppendLine($"Recorded baseline UTC: {Baseline.ObservedUtc:yyyy-MM-ddTHH:mm:ssZ}");
        }
        if (FirstSeen is not null)
        {
            text.AppendLine("First seen (UNVERIFIED local observation):")
                .AppendLine($"  Version: {FirstSeen.DllVersion}")
                .AppendLine($"  SHA-256: {FirstSeen.Sha256}")
                .AppendLine($"  Observed UTC: {FirstSeen.ObservedUtc:yyyy-MM-ddTHH:mm:ssZ}");
            text.AppendLine("This first observation is NOT verified original Microsoft DLL evidence.");
        }
        text.AppendLine($"Status: {Status}");
        if (!string.IsNullOrWhiteSpace(Warning)) text.AppendLine(Warning);
        if (!string.IsNullOrWhiteSpace(FirstSeenWarning)) text.AppendLine(FirstSeenWarning);
        text.AppendLine("A checksum difference cannot prove why the DLL changed. " +
                        "It may be a Windows update, manual replacement or another event.");
        text.AppendLine("Never use this metadata as permission to patch or restore a DLL.");
        return text.ToString();
    }
}

internal static class DllHealthMonitor
{
    internal static string LocalBaselineFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TermsrvPatcherUnified", "Health", "baseline.json");

    internal static string LocalFirstSeenFile => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TermsrvPatcherUnified", "Health", "first-seen.json");

    internal static DllHealthReport CheckLocal()
    {
        var info = SystemInfo.Read();
        return CheckWithFirstSeen(info.DllPath, info.DllVersion,
            LocalBaselineFile, LocalFirstSeenFile);
    }

    // Only the first local observation is automatic; there is never an
    // automatic verified-original or authenticated-recovery designation.
    internal static DllHealthReport CheckWithFirstSeen(
        string file, string version, string manualBaseline, string firstSeenPath)
    {
        var report = CheckFile(file, version, manualBaseline);
        DllHealthSnapshot firstSeen;
        try
        {
            firstSeen = ReadOrCreateFirstSeen(file, firstSeenPath, report.Current);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                   System.Security.SecurityException or InvalidDataException or
                                   JsonException or ArgumentException)
        {
            return report with
            {
                FirstSeenWarning = "First-seen observation unavailable (" +
                                   ex.GetType().Name + "). Existing file was not overwritten."
            };
        }
        string difference = firstSeen.DllVersion != report.Current.DllVersion
            ? "DLL version changed since first observation."
            : firstSeen.Sha256 != report.Current.Sha256 ||
              firstSeen.FileLength != report.Current.FileLength
                ? "DLL bytes differ from first observation, even though the version may match."
                : "The current DLL matches the first local observation.";
        return report with
        {
            FirstSeen = firstSeen,
            Status = report.Status == DllDriftStatus.NoBaseline
                ? firstSeen.DllVersion == report.Current.DllVersion &&
                  firstSeen.Sha256 == report.Current.Sha256 &&
                  firstSeen.FileLength == report.Current.FileLength
                    ? DllDriftStatus.FirstSeenUnverified
                    : firstSeen.DllVersion != report.Current.DllVersion
                        ? DllDriftStatus.FileVersionChanged : DllDriftStatus.BytesChanged
                : report.Status,
            Warning = report.Status == DllDriftStatus.NoBaseline
                ? difference + " This observation is UNVERIFIED and never a proof of an original DLL."
                : report.Warning,
            FirstSeenWarning = "First-seen comparison: " + difference
        };
    }

    private static DllHealthSnapshot ReadOrCreateFirstSeen(
        string dllPath, string firstSeenPath, DllHealthSnapshot current)
    {
        var target = Path.GetFullPath(firstSeenPath);
        if (!Path.GetExtension(target).Equals(".json", StringComparison.OrdinalIgnoreCase) ||
            Path.GetFullPath(dllPath).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid first-seen metadata path.");
        if (File.Exists(target))
        {
            if (new FileInfo(target).Length > 2048)
                throw new InvalidDataException("First-seen metadata exceeds the size limit.");
            var previous = JsonSerializer.Deserialize<DllHealthSnapshot>(File.ReadAllText(target))
                ?? throw new InvalidDataException("First-seen metadata is empty.");
            previous.Validate();
            return previous;
        }
        var directory = Path.GetDirectoryName(target)
            ?? throw new ArgumentException("First-seen metadata requires a directory.");
        Directory.CreateDirectory(directory);
        try
        {
            using var output = new FileStream(target, FileMode.CreateNew,
                FileAccess.Write, FileShare.None);
            using var writer = new StreamWriter(output, new UTF8Encoding(false));
            writer.Write(JsonSerializer.Serialize(current));
            writer.Flush();
        }
        catch (IOException) when (File.Exists(target))
        {
            // A simultaneous inspection may have created the first observation.
        }
        if (new FileInfo(target).Length > 2048)
            throw new InvalidDataException("First-seen metadata exceeds the size limit.");
        var firstSeen = JsonSerializer.Deserialize<DllHealthSnapshot>(File.ReadAllText(target))
            ?? throw new InvalidDataException("First-seen metadata is empty.");
        firstSeen.Validate();
        return firstSeen;
    }

    internal static DllHealthReport RecordLocalBaseline()
    {
        var info = SystemInfo.Read();
        return RecordBaseline(info.DllPath, info.DllVersion, LocalBaselineFile);
    }

    internal static DllHealthReport CheckFile(string file, string version, string baseline)
    {
        var current = Observe(file, version);
        if (!File.Exists(baseline))
            return new(current, null, DllDriftStatus.NoBaseline,
                "No saved baseline. Choose Set baseline only after independently verifying the DLL.");
        try
        {
            if (new FileInfo(baseline).Length > 2048)
                throw new InvalidDataException("Baseline exceeds its size limit.");
            var recorded = JsonSerializer.Deserialize<DllHealthSnapshot>(File.ReadAllText(baseline))
                ?? throw new InvalidDataException("Baseline is empty.");
            recorded.Validate();
            var status = recorded.DllVersion != current.DllVersion
                ? DllDriftStatus.FileVersionChanged
                : recorded.Sha256 != current.Sha256 || recorded.FileLength != current.FileLength
                    ? DllDriftStatus.BytesChanged : DllDriftStatus.Unchanged;
            return new(current, recorded, status, null);
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or
                                   IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new(current, null, DllDriftStatus.InvalidBaseline,
                "Saved baseline is unavailable or invalid; no trustworthy comparison was made.");
        }
    }

    internal static DllHealthReport RecordBaseline(string file, string version, string baseline)
    {
        var current = Observe(file, version);
        var target = Path.GetFullPath(baseline);
        if (!Path.GetExtension(target).Equals(".json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("DLL health baseline must be JSON.");
        if (Path.GetFullPath(file).Equals(target, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Refusing to overwrite the DLL with a health baseline.");

        var directory = Path.GetDirectoryName(target)
            ?? throw new ArgumentException("Baseline needs a directory.");
        Directory.CreateDirectory(directory);
        // A baseline is voluntarily stored in user-local data, not the protected
        // backup directory. Its value is informational, never a security input.
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                writer.Write(JsonSerializer.Serialize(current));
            File.Move(temporary, target, overwrite: true);
            return new(current, current, DllDriftStatus.Unchanged,
                "Operator-recorded baseline saved locally. It is not authenticated and is never used to authorize modifications.");
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static DllHealthSnapshot Observe(string file, string version)
    {
        if (!Path.GetFileName(file).Equals("termsrv.dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Health inspection is limited to termsrv.dll.");
        if (string.IsNullOrWhiteSpace(version) || version.Length > 160 ||
            version.Any(char.IsControl))
            throw new InvalidDataException("Invalid DLL version.");
        var info = new FileInfo(file);
        if (info.Length is < 128 or > 52428800)
            throw new InvalidDataException("DLL size is outside inspection bounds.");
        byte[] bytes = File.ReadAllBytes(file);
        if (bytes.LongLength != info.Length)
            throw new IOException("DLL changed while reading; repeat the inspection.");
        PeSafety.ReadOfflineDllSections(bytes);
        var state = new DllHealthSnapshot(DllHealthSnapshot.SchemaId, version,
            SystemInfo.Sha256(bytes), bytes.LongLength, DateTimeOffset.UtcNow);
        state.Validate();
        return state;
    }
}
