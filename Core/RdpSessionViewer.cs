using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Read-only Win32 Terminal Services API inventory. Never calls any WTS
/// disconnect/logoff/send-message APIs and never transmits session identities.
/// </summary>
public sealed record LocalRdpSession(int SessionId, string Station, string State, string Account);

internal static class RdpSessionViewer
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr StationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WtsEnumerateSessions(
        IntPtr server, int reserved, int version, out IntPtr buffer, out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WtsQuerySessionInformation(
        IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSFreeMemory")]
    private static extern void WtsFreeMemory(IntPtr buffer);

    internal static IReadOnlyList<LocalRdpSession> ReadLocal()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows WTS API is required.");
        if (!WtsEnumerateSessions(IntPtr.Zero, 0, 1, out var pointer, out int count))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot enumerate local RDP sessions.");
        try
        {
            if (count < 0 || count > 4096 || (count > 0 && pointer == IntPtr.Zero))
                throw new InvalidDataException("Unexpected Windows WTS session inventory size.");
            var result = new List<LocalRdpSession>(count);
            int size = Marshal.SizeOf<WtsSessionInfo>();
            for (int i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<WtsSessionInfo>(IntPtr.Add(pointer, checked(i * size)));
                string station = Marshal.PtrToStringUni(entry.StationName) ?? "";
                if (station.Length > 128) station = station[..128];
                string username = QueryText(entry.SessionId, 5);  // WTSUserName
                string domain = QueryText(entry.SessionId, 7);    // WTSDomainName
                var account = string.IsNullOrWhiteSpace(username) ? "(not available)" :
                    string.IsNullOrWhiteSpace(domain) ? username : domain + @"\" + username;
                result.Add(new LocalRdpSession(entry.SessionId, station,
                    StateName(entry.State), account));
            }
            return result.OrderBy(s => s.SessionId).ToArray();
        }
        finally
        {
            if (pointer != IntPtr.Zero) WtsFreeMemory(pointer);
        }
    }

    private static string QueryText(int sessionId, int infoClass)
    {
        if (!WtsQuerySessionInformation(IntPtr.Zero, sessionId, infoClass,
                out var buffer, out var length))
        {
            if (buffer != IntPtr.Zero) WtsFreeMemory(buffer);
            return "";
        }
        try
        {
            if (buffer == IntPtr.Zero || length < 2) return "";
            // WTS returns a NUL-terminated UTF-16 string; cap rendering and
            // never try to read outside the byte count reported by Windows.
            int maxCharacters = Math.Min((length / 2), 256);
            return (Marshal.PtrToStringUni(buffer, maxCharacters) ?? "")
                .TrimEnd('\0');
        }
        finally { if (buffer != IntPtr.Zero) WtsFreeMemory(buffer); }
    }

    internal static string StateName(int state) => state switch
    {
        0 => "Active",
        1 => "Connected",
        2 => "ConnectQuery",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listening",
        7 => "Reset",
        8 => "Down",
        9 => "Initializing",
        _ => "Unknown (" + state.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")"
    };
}
