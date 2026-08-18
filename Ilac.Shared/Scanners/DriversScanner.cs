using System.Diagnostics;
using System.Text;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class DriversScanner
{
    public List<Detection> Scan(ScanConfig config)
    {
        var results = new List<Detection>();
        if (!config.ScanDrivers) return results;

        results.AddRange(CheckVulnerableDrivers());
        results.AddRange(CheckTestSigning());
        results.AddRange(CheckRecentlyLoadedDrivers());

        return results;
    }

    private List<Detection> CheckRecentlyLoadedDrivers()
    {
        var results = new List<Detection>();
        var cutoff = DateTime.Now.AddMinutes(-30);

        try
        {
            // System event log, Event ID 20001 = driver install
            var log = new EventLog("System");
            for (int i = log.Entries.Count - 1; i >= 0 && i > log.Entries.Count - 500; i--)
            {
                try
                {
                    var entry = log.Entries[i];
                    if (entry.TimeGenerated < cutoff) break;
                    if (entry.InstanceId == 20001 || entry.EventID == 20001)
                    {
                        results.Add(new Detection
                        {
                            Category = "Recently Loaded Driver",
                            Name = $"Driver Install: {SafeStr(entry.Message, 100)}",
                            Detail = $"Driver installed at {entry.TimeGenerated:yyyy-MM-dd HH:mm:ss}: {SafeStr(entry.Message, 300)}",
                            Severity = 6,
                            Timestamp = entry.TimeGenerated
                        });
                    }
                }
                catch { }
            }
            log.Close();
        }
        catch { }

        // Also check setupapi.dev.log for recent driver installs
        try
        {
            var setupLog = Path.Combine(
                Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows",
                "inf", "setupapi.dev.log");
            if (File.Exists(setupLog))
            {
                var lines = File.ReadAllLines(setupLog);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Contains("Device Install", StringComparison.OrdinalIgnoreCase) ||
                        lines[i].Contains("Driver Install", StringComparison.OrdinalIgnoreCase))
                    {
                        // Look for a timestamp nearby
                        for (int j = i; j < Math.Min(i + 5, lines.Length); j++)
                        {
                            if (DateTime.TryParse(lines[j].Trim().TrimStart('>'), out var ts) && ts >= cutoff)
                            {
                                results.Add(new Detection
                                {
                                    Category = "Recently Loaded Driver",
                                    Name = $"SetupAPI Driver: {SafeStr(lines[i], 100)}",
                                    Detail = $"Driver install logged at {ts:yyyy-MM-dd HH:mm}: {SafeStr(lines[i], 250)}",
                                    Severity = 5,
                                    Timestamp = ts
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        catch { }

        return results;
    }

    private static string SafeStr(string s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
        return s.Length <= max ? s : s.Substring(0, max) + "…";
    }

    public List<string> GetLoadedDrivers()
    {
        var drivers = new List<string>();
        try
        {
            var psi = new ProcessStartInfo("sc", "query type=driver state=active")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return drivers;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            drivers = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(l => l.Trim().StartsWith("SERVICE_NAME", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim().Substring("SERVICE_NAME:".Length).Trim())
                .Where(n => !string.IsNullOrEmpty(n) && n != "null")
                .ToList();
        }
        catch { }
        return drivers;
    }

    private List<Detection> CheckVulnerableDrivers()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("sc", "query type=driver state=active")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // Known vulnerable/exploitable drivers (BYOVD)
            var vulnerableDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "gdrv", "aswsp", "aswsnf", "aswnet",
                "iqvw64", "rtcore64", "dbk64", "dbk32",
                "winring0x64", "winring0", "inpoutx64", "inpout",
                "speedfan", "cpuz", "cpuz142",
                "epp2", "eesys",
                "mhyprot", "mhyprot2", "mhyprotsvc",
                "kprocesshacker", "processhacker",
                "pcileech", "dma",
                "ntice", "softice",
                "injector", "mapper", "kdmapper",
                "xenos", "x64mapper"
            };

            var activeServices = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(l => l.Trim().StartsWith("SERVICE_NAME", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim().Substring("SERVICE_NAME:".Length).Trim())
                .ToList();

            foreach (var svc in activeServices)
            {
                var lower = svc.ToLower();
                foreach (var vuln in vulnerableDrivers)
                {
                    if (lower == vuln || lower.StartsWith(vuln + "."))
                    {
                        results.Add(new Detection
                        {
                            Category = "Driver",
                            Name = $"Vulnerable Driver: {svc}",
                            Detail = $"Known vulnerable/exploitable driver service active: {svc} - commonly used for BYOVD attacks",
                            Severity = 8
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return results;
    }

    private List<Detection> CheckTestSigning()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("bcdedit", "/enum")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // Parse for testsigning and nointegritychecks
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
                    trimmed.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new Detection
                    {
                        Category = "Boot Config",
                        Name = "Test Signing Mode Enabled",
                        Detail = "Test signing is ON - unsigned kernel drivers can be loaded, commonly used for cheat drivers",
                        Severity = 8
                    });
                }

                if (trimmed.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase) &&
                    trimmed.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new Detection
                    {
                        Category = "Boot Config",
                        Name = "Code Integrity Checks Disabled",
                        Detail = "Integrity checks are OFF - kernel tampering possible",
                        Severity = 7
                    });
                }
            }
        }
        catch { }
        return results;
    }
}
