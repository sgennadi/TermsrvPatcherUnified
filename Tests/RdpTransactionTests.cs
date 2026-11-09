using System.IO;
using System.ServiceProcess;
using TermsrvPatcherUnified.Core;

internal static class RdpTransactionTests
{
    private static int assertions;
    private static void Verify(bool condition, string reason)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException("RDP transaction QA: " + reason);
    }

    private sealed class FakeServiceProvider : IServiceControlProvider
    {
        internal readonly Dictionary<string, ServiceControllerStatus> States = new()
        {
            ["UmRdpService"] = ServiceControllerStatus.Stopped,
            ["SessionEnv"] = ServiceControllerStatus.Running,
            ["TermService"] = ServiceControllerStatus.Running
        };
        internal readonly List<string> Calls = [];
        internal string? FailStopName;
        internal string? FailStartName;
        internal string? MissingName;

        public IServiceControl Open(string name) => new FakeService(this, name);

        private sealed class FakeService : IServiceControl
        {
            private readonly FakeServiceProvider owner;
            private readonly string name;
            internal FakeService(FakeServiceProvider owner, string name)
            {
                this.owner = owner;
                this.name = name;
            }

            public ServiceControllerStatus Status
            {
                get
                {
                    if (owner.MissingName == name)
                        throw new InvalidOperationException("Simulated missing service.");
                    return owner.States[name];
                }
            }
            public void Refresh() { }
            public void Stop()
            {
                owner.Calls.Add("stop:" + name);
                owner.States[name] = ServiceControllerStatus.Stopped;
                if (owner.FailStopName == name)
                    throw new IOException("Injected failure AFTER stopping " + name);
            }
            public void Start()
            {
                owner.Calls.Add("start:" + name);
                if (owner.FailStartName == name)
                    throw new IOException("Injected failure while restarting " + name);
                owner.States[name] = ServiceControllerStatus.Running;
            }
            public void WaitForStatus(ServiceControllerStatus desired, TimeSpan timeout)
            {
                if (Status != desired) throw new System.TimeoutException("Injected wait failure.");
            }
            public void Dispose() { }
        }
    }

    internal static int Run()
    {
        var trace = new List<string>();
        int one = 0, two = 0, three = 0;
        RdpReversibleChange Edit(string label, int value, Action<int> put, Func<int> read)
        {
            int old = read();
            return new RdpReversibleChange(label,
                () => { trace.Add("apply:" + label); put(value); },
                () => { trace.Add("undo:" + label); put(old); },
                () => read() == value,
                () => read() == old);
        }

        RdpSettingsTransaction.Execute([
            Edit("one", 1, n => one = n, () => one),
            Edit("two", 2, n => two = n, () => two)
        ]);
        Verify(one == 1 && two == 2, "successful transaction commits all changes");
        Verify(trace.SequenceEqual(["apply:one", "apply:two"]),
            "successful plan uses forward order");
        Verify(three == 0, "unmentioned state remains unchanged");

        one = 0; two = 0; three = 0; trace.Clear();
        var second = new RdpReversibleChange("two",
            () => { trace.Add("apply:two"); two = 2; throw new IOException("Injected after-write failure"); },
            () => { trace.Add("undo:two"); two = 0; },
            () => two == 2, () => two == 0);
        bool rejected = false;
        try
        {
            RdpSettingsTransaction.Execute([
                Edit("one", 1, n => one = n, () => one),
                second,
                Edit("three", 3, n => three = n, () => three)
            ]);
        }
        catch (InvalidOperationException ex) { rejected = ex.InnerException is IOException; }
        Verify(rejected, "setter error is surfaced, never counted as success");
        Verify(one == 0 && two == 0 && three == 0,
            "all attempted mutations including throwing setter are reverted");
        Verify(trace.SequenceEqual(["apply:one", "apply:two", "undo:two", "undo:one"]),
            "reverse rollback executes even for a partially applied setter");

        one = 0; trace.Clear(); rejected = false;
        try
        {
            RdpSettingsTransaction.Execute([
                new RdpReversibleChange("readback",
                    () => { one = 1; trace.Add("apply"); },
                    () => { one = 0; trace.Add("undo"); },
                    () => false, () => one == 0)
            ]);
        }
        catch (InvalidOperationException ex) { rejected = ex.InnerException is IOException; }
        Verify(rejected && one == 0 && trace.SequenceEqual(["apply", "undo"]),
            "post-write readback mismatch causes verified rollback");

        one = 0; two = 0;
        AggregateException? incomplete = null;
        try
        {
            RdpSettingsTransaction.Execute([
                new RdpReversibleChange("one", () => one = 1, () => one = 0,
                    () => one == 1, () => one == 0),
                new RdpReversibleChange("two",
                    () => { two = 2; throw new IOException("Injected"); },
                    () => throw new IOException("Undo blocked"),
                    () => two == 2, () => two == 0)
            ]);
        }
        catch (AggregateException ex) { incomplete = ex; }
        Verify(incomplete?.InnerExceptions.Count == 2,
            "original failure and rollback failure are both retained");
        Verify(incomplete?.Message.Contains("INCOMPLETE", StringComparison.Ordinal) == true,
            "incomplete rollback is prominently reported");
        Verify(one == 0 && two == 2,
            "later rollback errors do not prevent restoration of earlier settings");

        one = 0;
        try
        {
            RdpSettingsTransaction.Execute([
                new RdpReversibleChange("failure", () => one = 1, () => one = 0,
                    () => one == 1, () => false)
                // Successful rollback normally needs no run; the mismatch below
                // ensures failures after a subsequent throwing setter are tracked.
            ]);
        }
        catch (Exception e) { throw new Exception("Unexpected transaction failure", e); }
        Verify(one == 1, "a successful transaction has no speculative rollback");

        one = 0; incomplete = null;
        try
        {
            RdpSettingsTransaction.Execute([
                new RdpReversibleChange("setter", () => { one = 1; throw new IOException(); },
                    () => one = 0, () => one == 1, () => false)
            ]);
        }
        catch (AggregateException ex) { incomplete = ex; }
        Verify(incomplete?.InnerExceptions.Count == 2 && one == 0,
            "unverifiable restoration is reported as incomplete even when bytes look restored");

        var simple = new FakeServiceProvider();
        using (var guard = new ServiceGuard(simple))
        {
            Verify(simple.States["TermService"] == ServiceControllerStatus.Stopped &&
                   simple.States["SessionEnv"] == ServiceControllerStatus.Stopped &&
                   simple.States["UmRdpService"] == ServiceControllerStatus.Stopped,
                "only originally running services are stopped");
            Verify(simple.Calls.SequenceEqual(["stop:SessionEnv", "stop:TermService"]),
                "service stop order preserves dependent services");
        }
        Verify(simple.States["TermService"] == ServiceControllerStatus.Running &&
               simple.States["SessionEnv"] == ServiceControllerStatus.Running &&
               simple.States["UmRdpService"] == ServiceControllerStatus.Stopped,
            "original service states restored; initially stopped services remain stopped");
        Verify(simple.Calls.TakeLast(2).SequenceEqual(["start:TermService", "start:SessionEnv"]),
            "service restart happens in dependency-safe order");

        var unstable = new FakeServiceProvider();
        unstable.States["TermService"] = ServiceControllerStatus.Paused;
        bool preflightRefused = false;
        try { using var _ = new ServiceGuard(unstable); }
        catch (InvalidOperationException) { preflightRefused = true; }
        Verify(preflightRefused && unstable.Calls.Count == 0,
            "transitional or paused services block all service writes");

        var missing = new FakeServiceProvider { MissingName = "TermService" };
        bool missingRefused = false;
        try { using var _ = new ServiceGuard(missing); }
        catch (InvalidOperationException) { missingRefused = true; }
        Verify(missingRefused && missing.Calls.Count == 0,
            "missing TermService refuses protected write preflight");
        var optional = new FakeServiceProvider { MissingName = "UmRdpService" };
        using (var guard = new ServiceGuard(optional))
        {
            Verify(optional.Calls.Contains("stop:TermService"),
                "missing optional companion is tolerated");
        }

        var stoppedThenFailed = new FakeServiceProvider { FailStopName = "SessionEnv" };
        bool stopRefused = false;
        try { using var _ = new ServiceGuard(stoppedThenFailed); }
        catch (IOException) { stopRefused = true; }
        Verify(stopRefused && stoppedThenFailed.States["SessionEnv"] ==
               ServiceControllerStatus.Running &&
               stoppedThenFailed.States["TermService"] == ServiceControllerStatus.Running,
            "failed partial stop restarts the affected service before rethrow");

        var failedRecovery = new FakeServiceProvider
        {
            FailStopName = "SessionEnv", FailStartName = "SessionEnv"
        };
        AggregateException? recoveryError = null;
        try { using var _ = new ServiceGuard(failedRecovery); }
        catch (AggregateException ex) { recoveryError = ex; }
        Verify(recoveryError?.InnerExceptions.Count == 2 &&
               recoveryError.Message.Contains("restarts failed", StringComparison.Ordinal),
            "constructor preserves both original stop and failed restart exceptions");

        var failAfterStop = new FakeServiceProvider { FailStartName = "TermService" };
        ServiceGuard scope = new(failAfterStop);
        scope.Dispose();
        Verify(scope.RestartFailures.Count == 1 &&
               failAfterStop.States["TermService"] == ServiceControllerStatus.Stopped,
            "service recovery errors remain visible to caller even after Dispose");
        scope.Dispose();
        Verify(scope.RestartFailures.Count == 1, "service recovery is idempotent");

        Console.WriteLine("PASS: " + assertions +
                          " synthetic RDP transaction and service recovery tests; no live registry/services/DLL touched.");
        return assertions;
    }
}
