using System.ServiceProcess;

namespace TermsrvPatcherUnified.Core;

// Avoids killing a shared svchost.exe. If a service cannot stop cleanly, abort.
internal sealed class ServiceGuard : IDisposable
{
    private readonly List<string> originallyRunning = [];
    private bool disposed;
    public List<Exception> RestartFailures { get; } = [];
    private static readonly string[] StopOrder = ["UmRdpService", "SessionEnv", "TermService"];
    private static readonly string[] StartOrder = ["TermService", "SessionEnv", "UmRdpService"];

    public ServiceGuard()
    {
        try
        {
            foreach (var name in StopOrder)
            {
                using var service = new ServiceController(name);
                try { _ = service.Status; }
                catch (InvalidOperationException) { continue; }
                if (service.Status == ServiceControllerStatus.Stopped) continue;
                originallyRunning.Add(name);
                if (service.Status != ServiceControllerStatus.StopPending)
                    service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                AuditLog.Append($"Stopped service {name}");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        foreach (var name in StartOrder)
        {
            if (!originallyRunning.Contains(name)) continue;
            try
            {
                using var service = new ServiceController(name);
                service.Refresh();
                if (service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }
                AuditLog.Append($"Restarted service {name}");
            }
            catch (Exception e)
            {
                AuditLog.Append($"IMPORTANT: Could not restart {name}: {e.Message}");
                RestartFailures.Add(new InvalidOperationException($"Cannot restart {name}", e));
            }
        }
    }
}
