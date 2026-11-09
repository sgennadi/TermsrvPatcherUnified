using System.Windows;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using TermsrvPatcherUnified.Core;

namespace TermsrvPatcherUnified;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, args) =>
            DiagnosticsBridge.Remember("Application", args.Exception);
        if (e.Args.Length > 0 && e.Args[0].Equals(UpdateInstallBridge.ProbeArgument, StringComparison.Ordinal))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(e.Args.Length == 2 ? UpdateInstallBridge.Probe(e.Args[1]) : 2);
            return;
        }
        if (e.Args.Length > 0 && e.Args[0].Equals(UpdateInstallBridge.HelperArgument, StringComparison.Ordinal))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(e.Args.Length == 2 ? UpdateInstallBridge.RunHelper(e.Args[1]) : 2);
            return;
        }
        if (e.Args.Length > 0 && e.Args[0].Equals("--inspect-file", StringComparison.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                if (e.Args.Length != 4 || !e.Args[2].Equals("--report", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Usage: --inspect-file <DLL path> --report <TXT path>");
                string input = Path.GetFullPath(e.Args[1]);
                string output = Path.GetFullPath(e.Args[3]);
                if (input.Equals(output, StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Report path must differ from the inspected file.");
                if (!Path.GetExtension(output).Equals(".txt", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Report output must have a .txt extension.");
                var report = DllScanner.Scan(input, null);
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                File.WriteAllText(output, report.AsText(), Encoding.UTF8);
                Environment.ExitCode = 0;
            }
            catch (Exception ex)
            {
                Environment.ExitCode = 2;
                AuditLog.Append("Read-only inspection CLI failed: " + ex.GetType().Name + ": " + ex.Message);
            }
            finally { Shutdown(); }
            return;
        }
        if (e.Args.Any(a => a.Equals("--reapply", StringComparison.OrdinalIgnoreCase)))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                // Headless is intended only for a separately configured, administrator-approved task.
                // It never generates a missing pattern automatically.
                if (!SystemInfo.IsAdministrator())
                    throw new UnauthorizedAccessException("Unattended --reapply requires an elevated administrator or an approved SYSTEM task.");
                using var engine = new TermsrvEngine(null);
                var plan = engine.Inspect();
                if (plan.State == PatchState.Ready) engine.Apply(plan);
                Environment.ExitCode = plan.State is PatchState.Ready or PatchState.AlreadyPatched ? 0 : 3;
                AuditLog.Append($"Headless inspection: {plan.State}, {plan.ProfileId}");
            }
            catch (Exception ex)
            {
                Environment.ExitCode = 4;
                AuditLog.Append("Headless apply failed: " + ex.GetType().Name + ": " + ex.Message);
            }
            finally { Shutdown(); }
            return;
        }
        // An offline-only GUI session skips the startup UAC prompt.
        // Protected Apply/Restore and RDP settings remain independently guarded.
        bool offlineStartup = e.Args.Length == 1 &&
            e.Args[0].Equals("--offline", StringComparison.OrdinalIgnoreCase);
        // The scanner remains usable without elevation; the full interactive manager
        // auto-prompts once for UAC instead of requiring it for CLI --inspect-file.
        if (!offlineStartup && !SystemInfo.IsAdministrator())
        {
            try
            {
                var executable = Environment.ProcessPath
                    ?? throw new InvalidOperationException("Cannot determine current executable path.");
                Process.Start(new ProcessStartInfo(executable)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = AppContext.BaseDirectory
                });
                Shutdown();
                return;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                // A refused UAC prompt leaves the GUI read-only. Apply/Restore/Settings
                // will still refuse writes via their own administrator guards.
                MessageBox.Show("Administrator elevation was cancelled. You can inspect files, but cannot apply changes.",
                    "TermsrvPatcher Unified", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not request administrator elevation: " + ex.Message,
                    "TermsrvPatcher Unified", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        MainWindow = new MainWindow(offlineStartup);
        MainWindow.Show();
    }
}
