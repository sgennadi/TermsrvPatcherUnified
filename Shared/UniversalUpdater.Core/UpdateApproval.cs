namespace UniversalUpdater;

/// <summary>
/// Trust must come from a platform signature verifier + administrator policy,
/// not GitHub SHA-256 alone. This version does not silently install any package.
/// </summary>
public static class UpdateApproval
{
    public static bool NeedsManualApproval(bool signatureVerified, bool pinnedPublisherMatched,
        bool administratorAutoInstallEnabled, bool userAutoInstallEnabled,
        bool failureHold, bool isPrerelease, bool prereleaseAllowed)
    {
        return !UpdatePolicy.CanAutomaticallyInstall(
            administratorAutoInstallEnabled, userAutoInstallEnabled,
            pinnedPublisherMatched, signatureVerified, failureHold, false,
            isPrerelease, prereleaseAllowed);
    }
}
