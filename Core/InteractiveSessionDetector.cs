using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TermsrvPatcherUnified.Core;

internal enum SessionKind { Console, Remote, Unknown }

/// <summary>
/// Detects whether the CURRENT interactive GUI process belongs to an RDP
/// session. Task Scheduler / SYSTEM worker starts in session 0; this check
/// is deliberately evaluated by the requesting GUI immediately before Apply.
/// Uncertain sessions use the isolated path rather than risking RDP teardown.
/// </summary>
internal static class InteractiveSessionDetector
{
    private const int WtsClientProtocolType = 16;
    private const int SmRemoteSession = 0x1000;

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WtsQuerySessionInformation(
        IntPtr server, int sessionId, int infoClass, out IntPtr buffer,
        out int bytesReturned);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSFreeMemory")]
    private static extern void WtsFreeMemory(IntPtr buffer);

    [DllImport("user32.dll", EntryPoint = "GetSystemMetrics")]
    private static extern int GetSystemMetrics(int index);

    internal static SessionKind Classify(ushort? protocol, bool remoteMetric)
    {
        // Two independent OS observations: either one indicating remote
        // takes precedence over a stale console classification.
        if (remoteMetric) return SessionKind.Remote;
        return protocol switch
        {
            0 => SessionKind.Console,
            1 or 2 => SessionKind.Remote, // ICA or RDP client transport
            _ => SessionKind.Unknown
        };
    }

    internal static SessionKind Detect()
    {
        if (!OperatingSystem.IsWindows()) return SessionKind.Unknown;
        bool remoteMetric = false;
        try { remoteMetric = GetSystemMetrics(SmRemoteSession) != 0; }
        catch (DllNotFoundException) { /* Protected fallback below. */ }
        catch (EntryPointNotFoundException) { /* Protected fallback below. */ }
        ushort? protocol = null;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            using var process = Process.GetCurrentProcess();
            // Session 0 is non-interactive. Never call it a console user.
            if (process.SessionId > 0 &&
                WtsQuerySessionInformation(IntPtr.Zero, process.SessionId,
                    WtsClientProtocolType, out buffer, out var length) &&
                buffer != IntPtr.Zero && length >= sizeof(short))
                protocol = unchecked((ushort)Marshal.ReadInt16(buffer));
        }
        catch (Exception ex) when (ex is InvalidOperationException or
                                   DllNotFoundException or EntryPointNotFoundException)
        {
            // No untrusted environment variable or client-controlled
            // SESSIONNAME fallback: ambiguous means isolated execution.
        }
        finally
        {
            if (buffer != IntPtr.Zero) WtsFreeMemory(buffer);
        }
        return Classify(protocol, remoteMetric);
    }

    internal static bool RequiresIndependentExecutor() => Detect() != SessionKind.Console;
}
