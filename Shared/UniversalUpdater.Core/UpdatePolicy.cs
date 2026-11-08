namespace UniversalUpdater;

/// <summary>Pure, side-effect-free policy. A hash alone is not publisher authentication.</summary>
public static class UpdatePolicy
{
    public static bool CanCheck(bool administratorDisabled) => !administratorDisabled;

    public static bool CanAutomaticallyInstall(
        bool administratorAllowed,
        bool userEnabled,
        bool trustedSignerConfigured,
        bool signatureVerified,
        bool rollbackOrFailureHold,
        bool isRollback,
        bool isPrerelease,
        bool prereleaseApproved)
    {
        return administratorAllowed && userEnabled && trustedSignerConfigured &&
               signatureVerified && !rollbackOrFailureHold && !isRollback &&
               (!isPrerelease || prereleaseApproved);
    }

    public static bool ShouldCheck(
        DateTimeOffset now,
        DateTimeOffset? lastSuccessful,
        DateTimeOffset? lastAttempt,
        TimeSpan? successInterval = null,
        TimeSpan? failedRetryInterval = null)
    {
        var success = successInterval ?? TimeSpan.FromHours(24);
        var retry = failedRetryInterval ?? TimeSpan.FromHours(2);
        if (success <= TimeSpan.Zero || retry <= TimeSpan.Zero) throw new ArgumentOutOfRangeException();
        if (lastSuccessful is { } checkedAt && now >= checkedAt && now - checkedAt < success)
            return false;
        if (lastAttempt is { } attempted && now >= attempted &&
            (lastSuccessful is null || attempted > lastSuccessful) && now - attempted < retry)
            return false;
        return true;
    }
}
