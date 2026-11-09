using System.Security.AccessControl;
using System.Security.Principal;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Machine-wide, administrator-only gate for protected Apply/Restore and RDP settings.
/// Acquire fails without waiting: a contended or untrusted mutex never stops services.
/// The owner must always dispose on the same thread that acquired the mutex.
/// </summary>
internal sealed class OperationLock : IDisposable
{
    internal const string DefaultName = @"Global\TermsrvPatcherUnified.Operation";
    private readonly Mutex handle;
    private bool owned;
    public bool WasAbandoned { get; }

    private OperationLock(Mutex handle, bool abandoned)
    {
        this.handle = handle;
        owned = true;
        WasAbandoned = abandoned;
    }

    internal static OperationLock Acquire(string name = DefaultName)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Operation locking requires Windows.");
        if (!SystemInfo.IsAdministrator())
            throw new UnauthorizedAccessException("Protected operation requires elevation.");
        if (!name.StartsWith(@"Global\TermsrvPatcherUnified.", StringComparison.Ordinal) ||
            name.Length > 128 || name.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or '\\')))
            throw new ArgumentException("Invalid protected operation lock name.", nameof(name));

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new MutexSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(admins);
        security.AddAccessRule(new MutexAccessRule(admins, MutexRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new MutexAccessRule(system, MutexRights.FullControl, AccessControlType.Allow));

        // Creating without ownership avoids a branch where createdNew=true would
        // implicitly acquire; the same zero-timeout wait is used in all cases.
        Mutex mutex;
        try { mutex = MutexAcl.Create(false, name, out _, security); }
        catch (UnauthorizedAccessException ex)
        {
            throw new UnauthorizedAccessException("Existing operation lock cannot be opened by an administrator.", ex);
        }

        try
        {
            // An unprivileged process can precreate the name. Never trust or use
            // an existing object whose owner/ACL differs from our protected one.
            var liveSecurity = mutex.GetAccessControl();
            var owner = liveSecurity.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!liveSecurity.AreAccessRulesProtected ||
                owner is null || (!owner.Equals(admins) && !owner.Equals(system)))
                throw new UnauthorizedAccessException("Operation lock owner or inherited ACL is untrusted.");
            foreach (MutexAccessRule rule in liveSecurity.GetAccessRules(
                         includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow ||
                    rule.IdentityReference is not SecurityIdentifier sid)
                    continue;
                if (!sid.Equals(admins) && !sid.Equals(system) &&
                    (rule.MutexRights & (MutexRights.Synchronize | MutexRights.Modify |
                                         MutexRights.ChangePermissions | MutexRights.TakeOwnership)) != 0)
                    throw new UnauthorizedAccessException("Operation lock has an untrusted mutating ACL entry.");
            }

            bool acquired;
            bool abandoned = false;
            try { acquired = mutex.WaitOne(TimeSpan.Zero); }
            catch (AbandonedMutexException)
            {
                acquired = true;
                abandoned = true;
            }
            if (!acquired)
                throw new InvalidOperationException("Another protected operation is active. No DLL or service was changed.");
            return new OperationLock(mutex, abandoned);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (!owned) return;
        owned = false;
        try { handle.ReleaseMutex(); }
        finally { handle.Dispose(); }
    }
}
