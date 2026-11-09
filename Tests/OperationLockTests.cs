using TermsrvPatcherUnified.Core;

internal static class OperationLockTests
{
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows() || !SystemInfo.IsAdministrator())
        {
            Console.WriteLine("SKIP: operation-lock ACL tests require elevated Windows.");
            return 0;
        }
        int checkedCount = 0;
        using (var first = OperationLock.Acquire())
        {
            if (first.WasAbandoned) throw new Exception("Fresh lock unexpectedly abandoned.");
            checkedCount++;
            // A mutex is reentrant on one thread, so test contention on a
            // separate thread that has no inherited mutex ownership.
            var refused = Task.Run(() =>
            {
                try { using var second = OperationLock.Acquire(); return false; }
                catch (InvalidOperationException) { return true; }
            }).GetAwaiter().GetResult();
            if (!refused) throw new Exception("Concurrent thread unexpectedly acquired live lock.");
            checkedCount++;
        }
        using (var second = OperationLock.Acquire())
        {
            if (second.WasAbandoned) throw new Exception("Released lock was not cleaned up.");
            checkedCount++;
        }
        Console.WriteLine($"PASS: {checkedCount} protected cross-thread operation-lock checks.");
        return checkedCount;
    }
}
