using System.Diagnostics;

namespace TermsrvPatcherUnified.Core;

public static class CommandRunner
{
    public static (int ExitCode, string Output) Run(string exe, int seconds, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Cannot start " + exe);
        // Drain both streams to prevent deadlock on full redirected pipes.
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(seconds * 1000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{exe} timed out after {seconds} seconds.");
        }
        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + "\n" + stderr.Result);
    }

    public static void Required(string exe, int seconds, params string[] args)
    {
        var r = Run(exe, seconds, args);
        if (r.ExitCode != 0)
            throw new InvalidOperationException($"{exe} failed with exit {r.ExitCode}: {r.Output.Trim()}");
    }
}
