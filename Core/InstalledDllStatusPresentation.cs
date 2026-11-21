using System.Windows.Media;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Shared presentation policy for the simple and advanced installed-DLL status.
/// Recovery readiness is intentionally not used to classify the current DLL.
/// </summary>
internal static class InstalledDllStatusPresentation
{
    internal static SolidColorBrush BrushFor(InstalledDllKind kind) =>
        new(kind switch
        {
            InstalledDllKind.Patched => Color.FromRgb(11, 135, 76),
            InstalledDllKind.NotPatched => Color.FromRgb(40, 88, 157),
            _ => Color.FromRgb(160, 92, 14)
        });
}
