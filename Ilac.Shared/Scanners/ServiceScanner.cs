using System.Diagnostics;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class ServiceScanner
{
    public List<BypassEntry> Scan(ScanConfig config)
    {
        var results = new List<BypassEntry>();
        if (!config.ScanServices) return results;

        // Only flag critical services that are stopped
        // Don't flag common "optional" services that many users disable

        var sysMain = GetServiceState("SysMain");
        if (sysMain == "STOPPED")
        {
            results.Add(new BypassEntry
            {
                Type = "SysMain Stopped",
                Detail = "SysMain (Superfetch) is stopped - prevents prefetch generation (may be manually disabled)",
                Severity = 5
            });
        }

        var eventLog = GetServiceState("EventLog");
        if (eventLog == "STOPPED")
        {
            results.Add(new BypassEntry
            {
                Type = "EventLog Stopped",
                Detail = "EventLog service is stopped - critical logging disabled",
                Severity = 8
            });
        }

        return results;
    }

    private string? GetServiceState(string serviceName)
    {
        try
        {
            var psi = new ProcessStartInfo("sc", $"query {serviceName}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return null;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            if (output.Contains("RUNNING")) return "RUNNING";
            if (output.Contains("STOPPED")) return "STOPPED";
            if (output.Contains("not exist", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("not found", StringComparison.OrdinalIgnoreCase))
                return "NOT_FOUND";
            return "UNKNOWN";
        }
        catch { return null; }
    }
}
