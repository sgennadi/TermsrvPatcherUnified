using System.Windows;

namespace TermsrvPatcherUnified.Core;

/// <summary>
/// Limit default window dimensions to the current usable work area (DIPs).
/// This prevents tall windows, especially at 150%-200% desktop scaling,
/// from pushing their primary buttons below the taskbar.
/// </summary>
internal static class WindowLayout
{
    internal static Rect FitBounds(Rect workArea, double preferredWidth, double preferredHeight,
        double edgePadding = 20)
    {
        if (workArea.Width <= 0 || workArea.Height <= 0)
            return new Rect(0, 0, preferredWidth, preferredHeight);
        double availableWidth = Math.Max(400, workArea.Width - 2 * edgePadding);
        double availableHeight = Math.Max(350, workArea.Height - 2 * edgePadding);
        double width = Math.Min(preferredWidth, availableWidth);
        double height = Math.Min(preferredHeight, availableHeight);
        return new Rect(
            workArea.Left + (workArea.Width - width) / 2,
            workArea.Top + (workArea.Height - height) / 2,
            width, height);
    }

    internal static void FitToWorkArea(Window window)
    {
        if (window.WindowState != WindowState.Normal) return;
        var work = SystemParameters.WorkArea;
        if (work.Width < 400 || work.Height < 350) return;
        var bounds = FitBounds(work, window.Width, window.Height);
        window.MinWidth = Math.Min(window.MinWidth, bounds.Width);
        window.MinHeight = Math.Min(window.MinHeight, bounds.Height);
        window.Width = bounds.Width;
        window.Height = bounds.Height;
        window.Left = bounds.Left;
        window.Top = bounds.Top;
    }
}
