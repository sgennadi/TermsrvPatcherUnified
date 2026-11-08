using System.Text.Json;
using System.Windows;

namespace TermsrvPatcherUnified.Core;

public static class WindowSettings
{
    private sealed record Geometry(double Left, double Top, double Width, double Height);
    private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TermsrvPatcherUnified", "window.json");

    public static void Restore(Window window)
    {
        try
        {
            if (!File.Exists(FilePath)) return;
            var value = JsonSerializer.Deserialize<Geometry>(File.ReadAllText(FilePath));
            if (value is null || !double.IsFinite(value.Width) || !double.IsFinite(value.Height) ||
                !double.IsFinite(value.Left) || !double.IsFinite(value.Top) ||
                value.Width < window.MinWidth || value.Height < window.MinHeight) return;
            // Avoid restoring the whole window outside the current virtual desktop.
            if (value.Left + 150 < SystemParameters.VirtualScreenLeft ||
                value.Top + 100 < SystemParameters.VirtualScreenTop ||
                value.Left > SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - 150 ||
                value.Top > SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - 100) return;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Left = value.Left;
            window.Top = value.Top;
            window.Width = value.Width;
            window.Height = value.Height;
        }
        catch { /* Invalid window settings should not prevent startup. */ }
    }

    public static void Save(Window window)
    {
        try
        {
            var bounds = window.WindowState == WindowState.Normal
                ? new Rect(window.Left, window.Top, window.Width, window.Height)
                : window.RestoreBounds;
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(new Geometry(bounds.Left, bounds.Top,
                bounds.Width, bounds.Height)));
        }
        catch { /* Window positions are optional. */ }
    }
}
