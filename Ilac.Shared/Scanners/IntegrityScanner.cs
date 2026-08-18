using System.Diagnostics;
using Microsoft.Win32;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class IntegrityScanner
{
    public List<BypassEntry> Scan(ScanConfig config)
    {
        var results = new List<BypassEntry>();
        if (!config.ScanIntegrity) return results;

        results.AddRange(CheckPrefetchIntegrity());
        results.AddRange(CheckBAMIntegrity());
        results.AddRange(CheckTimeChange());
        results.AddRange(CheckTestSigning());
        results.AddRange(CheckLogDeletion());

        return results;
    }

    private List<BypassEntry> CheckPrefetchIntegrity()
    {
        var results = new List<BypassEntry>();
        try
        {
            var prefetchDir = Path.Combine(
                Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows", "Prefetch");

            // Check if SysMain (Superfetch) service is running - if not, prefetch is disabled by the system
            var sysMain = GetServiceState("SysMain");
            if (sysMain == "STOPPED")
            {
                results.Add(new BypassEntry
                {
                    Type = "SysMain Disabled",
                    Detail = "SysMain (Superfetch) service is stopped - prefetch will not be generated",
                    Severity = 6
                });
                // Don't flag missing prefetch files as "manually cleaned" if the service is stopped
                return results;
            }

            // Check if prefetch is enabled in registry
            var prefetchEnabled = IsPrefetchEnabled();
            if (!prefetchEnabled)
            {
                results.Add(new BypassEntry
                {
                    Type = "Prefetch Disabled",
                    Detail = "Prefetch is disabled in registry - execution traces will not be generated",
                    Severity = 4
                });
                return results;
            }

            // Only flag as "cleaned" if prefetch is enabled but directory is empty
            if (Directory.Exists(prefetchDir))
            {
                var pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
                if (pfFiles.Length == 0)
                {
                    results.Add(new BypassEntry
                    {
                        Type = "Prefetch Cleaned",
                        Detail = "Prefetch is enabled but no .pf files found - may have been manually cleaned",
                        Severity = 7
                    });
                }
            }
        }
        catch { }
        return results;
    }

    private bool IsPrefetchEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (key == null) return true; // Default is enabled

            var enablePrefetch = key.GetValue("EnablePrefetch");
            if (enablePrefetch != null)
            {
                var val = Convert.ToInt32(enablePrefetch);
                // 0 = disabled, 1 = app launch prefetch, 2 = boot prefetch, 3 = both
                return val != 0;
            }
            return true;
        }
        catch { return true; }
    }

    private List<BypassEntry> CheckBAMIntegrity()
    {
        var results = new List<BypassEntry>();
        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            if (sid == null) return results;

            var bamPaths = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                @"SYSTEM\CurrentControlSet\Services\bam\UserSettings"
            };

            bool bamBaseExists = false;
            bool userHasEntries = false;

            foreach (var basePath in bamPaths)
            {
                try
                {
                    using var parentKey = Registry.LocalMachine.OpenSubKey(basePath);
                    if (parentKey == null) continue;

                    bamBaseExists = true;

                    // Check current user SID
                    using var sidKey = parentKey.OpenSubKey(sid);
                    if (sidKey != null)
                    {
                        var values = sidKey.GetValueNames();
                        if (values.Length > 0)
                        {
                            userHasEntries = true;
                            break;
                        }
                    }

                    // Check all user SIDs
                    foreach (var subKeyName in parentKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = parentKey.OpenSubKey(subKeyName);
                            if (subKey != null && subKey.GetValueNames().Length > 0)
                            {
                                userHasEntries = true;
                                break;
                            }
                        }
                        catch { }
                    }
                    if (userHasEntries) break;
                }
                catch { }
            }

            // Only flag as tampered if BAM base key exists but has no entries
            // If BAM base key doesn't exist at all, it might just not be configured on this Windows build
            if (bamBaseExists && !userHasEntries)
            {
                results.Add(new BypassEntry
                {
                    Type = "BAM Cleared",
                    Detail = "BAM registry key exists but contains no execution entries - may have been wiped",
                    Severity = 6
                });
            }
            else if (!bamBaseExists)
            {
                // Check if the BAM service itself exists
                try
                {
                    using var bamSvcKey = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\bam");
                    if (bamSvcKey != null)
                    {
                        results.Add(new BypassEntry
                        {
                            Type = "BAM UserSettings Missing",
                            Detail = "BAM service is registered but UserSettings key not found - may have been tampered",
                            Severity = 5
                        });
                    }
                }
                catch { }
            }
        }
        catch
        {
            // Don't flag access errors as bypass attempts
        }
        return results;
    }

    private List<BypassEntry> CheckTimeChange()
    {
        var results = new List<BypassEntry>();
        try
        {
            var psi = new ProcessStartInfo("w32tm", "/query /status")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                if (output.Contains("Not Supported", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new BypassEntry
                    {
                        Type = "Time Sync Disabled",
                        Detail = "Windows Time Service is not synchronizing",
                        Severity = 3
                    });
                }
            }
        }
        catch { }
        return results;
    }

    private List<BypassEntry> CheckTestSigning()
    {
        var results = new List<BypassEntry>();
        try
        {
            var psi = new ProcessStartInfo("bcdedit", "/enum")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                // More careful parsing - check for testsigning specifically
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                bool inCurrentEntry = false;
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();

                    // Check for testsigning in the current boot entry
                    if (trimmed.StartsWith("Windows Boot Loader", StringComparison.OrdinalIgnoreCase))
                        inCurrentEntry = true;
                    else if (trimmed.StartsWith("Windows Boot Manager", StringComparison.OrdinalIgnoreCase))
                        inCurrentEntry = false;

                    if (inCurrentEntry && trimmed.Contains("testsigning", StringComparison.OrdinalIgnoreCase))
                    {
                        // Check if it says "Yes"
                        if (trimmed.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new BypassEntry
                            {
                                Type = "Test Signing Enabled",
                                Detail = "Test signing mode is ON - unsigned kernel drivers can be loaded",
                                Severity = 8
                            });
                        }
                    }
                }
            }
        }
        catch { }
        return results;
    }

    private List<BypassEntry> CheckLogDeletion()
    {
        var results = new List<BypassEntry>();
        try
        {
            // Check Security log for event 1102 (audit log cleared)
            var log = new EventLog("Security");
            var entriesCount = log.Entries.Count;

            // Only flag if Security log has very few entries AND system has been running for a while
            var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
            if (entriesCount < 50 && uptime.TotalHours > 24)
            {
                results.Add(new BypassEntry
                {
                    Type = "Security Log Cleared",
                    Detail = $"Only {entriesCount} entries in Security log after {uptime.TotalHours:F0}h uptime - possibly cleared",
                    Severity = 6
                });
            }

            log.Close();
        }
        catch { }
        return results;
    }

    private string GetServiceState(string serviceName)
    {
        try
        {
            var psi = new ProcessStartInfo("sc", $"query {serviceName}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return "UNKNOWN";
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            if (output.Contains("RUNNING")) return "RUNNING";
            if (output.Contains("STOPPED")) return "STOPPED";
            if (output.Contains("not exist", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("not found", StringComparison.OrdinalIgnoreCase))
                return "NOT_FOUND";
            return "UNKNOWN";
        }
        catch { return "UNKNOWN"; }
    }
}
