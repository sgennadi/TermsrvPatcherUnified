using System.ServiceProcess;

namespace TermsrvPatcherUnified.Core;

internal interface IServiceControl : IDisposable
{
    ServiceControllerStatus Status { get; }
    void Refresh();
    void Stop();
    void Start();
    void WaitForStatus(ServiceControllerStatus desired, TimeSpan timeout);
}

internal interface IServiceControlProvider
{
    IServiceControl Open(string name);
}

internal sealed class WindowsServiceControlProvider : IServiceControlProvider
{
    public IServiceControl Open(string name) => new WindowsServiceControl(name);

    private sealed class WindowsServiceControl : IServiceControl
    {
        private readonly ServiceController service;
        internal WindowsServiceControl(string name) => service = new ServiceController(name);
        public ServiceControllerStatus Status => service.Status;
        public void Refresh() => service.Refresh();
        public void Stop() => service.Stop();
        public void Start() => service.Start();
        public void WaitForStatus(ServiceControllerStatus desired, TimeSpan timeout)
            => service.WaitForStatus(desired, timeout);
        public void Dispose() => service.Dispose();
    }
}

/// <summary>
/// State-preserving local service stop/restart scope. Preflight reads every
/// service state BEFORE stopping any of them and refuses transitional/paused
/// states. Recovery attempts every originally running service even after errors.
/// No forced process termination or Windows security policy changes.
/// </summary>
internal sealed class ServiceGuard : IDisposable
{
    private static readonly string[] StopOrder = ["UmRdpService", "SessionEnv", "TermService"];
    private static readonly string[] StartOrder = ["TermService", "SessionEnv", "UmRdpService"];
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private readonly IServiceControlProvider provider;
    private readonly HashSet<string> originallyRunning = new(StringComparer.Ordinal);
    private bool disposed;

    public List<Exception> RestartFailures { get; } = [];

    public ServiceGuard() : this(new WindowsServiceControlProvider()) { }

    internal ServiceGuard(IServiceControlProvider controller)
    {
        provider = controller ?? throw new ArgumentNullException(nameof(controller));
        var initial = new Dictionary<string, ServiceControllerStatus?>(
            StringComparer.Ordinal);

        // A failure to inspect service state must not cause a partially stopped system.
        // Some Windows builds omit optional companion services; TermService is mandatory.
        foreach (var name in StopOrder)
        {
            using var service = provider.Open(name);
            ServiceControllerStatus state;
            try { state = service.Status; }
            catch (InvalidOperationException) when (name != "TermService")
            {
                initial[name] = null;
                continue;
            }

            if (state is not (ServiceControllerStatus.Running or ServiceControllerStatus.Stopped))
                throw new InvalidOperationException(
                    "RDP service " + name + " is not in a stable Running/Stopped state. No services stopped.");
            initial[name] = state;
        }

        try
        {
            foreach (var name in StopOrder)
            {
                if (initial[name] != ServiceControllerStatus.Running) continue;
                using var service = provider.Open(name);
                service.Refresh();
                if (service.Status != ServiceControllerStatus.Running)
                    throw new InvalidOperationException(
                        "RDP service " + name + " state changed after preflight. Recovery will be attempted.");
                // Remember BEFORE calling Stop: a failed Stop may still have stopped the service.
                originallyRunning.Add(name);
                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, Timeout);
                AuditLog.Append("Stopped service " + name);
            }
        }
        catch (Exception original)
        {
            Dispose();
            if (RestartFailures.Count != 0)
                throw new AggregateException(
                    "RDP service stop failed and one or more service restarts failed; " +
                    "local console recovery may be required.",
                    new[] { original }.Concat(RestartFailures));
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
                using var service = provider.Open(name);
                service.Refresh();
                if (service.Status != ServiceControllerStatus.Running)
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, Timeout);
                }
                AuditLog.Append("Restarted service " + name);
            }
            catch (Exception e)
            {
                // Avoid including arbitrary exception messages/paths in durable logs.
                AuditLog.Append("IMPORTANT: Could not restart " + name + " (" +
                    e.GetType().Name + ").");
                RestartFailures.Add(new InvalidOperationException(
                    "Cannot restart " + name, e));
            }
        }
    }
}
