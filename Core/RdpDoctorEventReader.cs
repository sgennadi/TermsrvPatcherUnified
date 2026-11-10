using System.Diagnostics.Eventing.Reader;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Bounded read-only event metadata (no Message, user, IP or XML payload).
/// A missing channel is UNKNOWN, never a healthy remote-connection claim.
/// </summary>
internal static class RdpDoctorEventReader
{
    private static readonly (string Channel, string Label)[] Channels =
    [
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "LocalSessionManager"),
        ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "RemoteConnectionManager"),
        ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "RdpCoreTS")
    ];

    internal static (IReadOnlyList<RdpDoctorEvent> Events, IReadOnlyList<string> Warnings)
        ReadRecent(TimeSpan window)
    {
        var events = new List<RdpDoctorEvent>();
        var warnings = new List<string>();
        if (!OperatingSystem.IsWindows())
        {
            warnings.Add("Event logs require Windows.");
            return (events, warnings);
        }
        if (window <= TimeSpan.Zero || window > TimeSpan.FromDays(7))
        {
            warnings.Add("Invalid requested event time window.");
            return (events, warnings);
        }
        DateTimeOffset earliest = DateTimeOffset.UtcNow - window;
        foreach (var (channel, label) in Channels)
        {
            try
            {
                // Reverse-order enumeration with hard per-channel and total caps.
                var query = new EventLogQuery(channel, PathType.LogName, "*")
                {
                    ReverseDirection = true,
                    TolerateQueryErrors = false
                };
                using var reader = new EventLogReader(query);
                for (int n = 0; n < 45 && events.Count < 120; n++)
                {
                    using EventRecord? record = reader.ReadEvent();
                    if (record is null) break;
                    DateTime? time = record.TimeCreated;
                    if (!time.HasValue) continue;
                    var utc = new DateTimeOffset(time.Value).ToUniversalTime();
                    if (utc < earliest) break;
                    string level = MapLevel(record.Level);
                    events.Add(new(utc, label, record.Id, level));
                }
            }
            catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or
                                       InvalidOperationException or ArgumentException or
                                       System.Security.SecurityException or
                                       System.ComponentModel.Win32Exception)
            {
                warnings.Add(label + ": channel unavailable (" + ex.GetType().Name + ").");
            }
        }
        return (events.OrderByDescending(e => e.OccurredUtc).Take(120).ToArray(),
            warnings.ToArray());
    }

    internal static string MapLevel(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "Unknown"
    };
}
