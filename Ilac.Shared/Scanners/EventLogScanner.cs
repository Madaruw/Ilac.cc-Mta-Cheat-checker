using System.Diagnostics;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class EventLogScanner
{
    public List<Detection> Scan(ScanConfig config)
    {
        var results = new List<Detection>();
        if (!config.ScanEventLogs) return results;

        // Security log — only check last 200 entries (fast)
        try
        {
            var log = new EventLog("Security");
            var count = Math.Min(log.Entries.Count, 200);
            for (int i = log.Entries.Count - 1; i >= 0 && i > log.Entries.Count - count - 1; i--)
            {
                try
                {
                    var entry = log.Entries[i];
                    if (entry.TimeGenerated < DateTime.Now.AddDays(-7)) break;

                    if (entry.InstanceId == 1102)
                    {
                        results.Add(new Detection
                        {
                            Category = "Event Log",
                            Name = "Security Log Cleared",
                            Detail = $"Security log was cleared at {entry.TimeGenerated:yyyy-MM-dd HH:mm:ss}",
                            Severity = 9,
                            Timestamp = entry.TimeGenerated
                        });
                    }

                    if (entry.InstanceId == 4688)
                    {
                        var msg = entry.Message?.ToLower() ?? "";
                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            if (msg.Contains(cheat.Key.ToLower()))
                            {
                                results.Add(new Detection
                                {
                                    Category = "Process Creation",
                                    Name = $"Cheat Executed: {cheat.Key}",
                                    Detail = $"{cheat.Value} - Executed at {entry.TimeGenerated:yyyy-MM-dd HH:mm:ss}",
                                    Severity = 9,
                                    Timestamp = entry.TimeGenerated
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
            log.Close();
        }
        catch { }

        // PowerShell log — only check last 50 entries
        try
        {
            var psLog = new EventLog("Windows PowerShell");
            var psCount = Math.Min(psLog.Entries.Count, 50);
            for (int i = psLog.Entries.Count - 1; i >= 0 && i > psLog.Entries.Count - psCount - 1; i--)
            {
                try
                {
                    var entry = psLog.Entries[i];
                    var msg = entry.Message ?? "";

                    if (msg.Contains("Engine state", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("ProviderName", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("NewProviderState", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("NewEngineState", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (msg.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("-WindowStyle Hidden", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(new Detection
                        {
                            Category = "PowerShell",
                            Name = "Suspicious PowerShell Command",
                            Detail = $"Suspicious PS command at {entry.TimeGenerated:yyyy-MM-dd HH:mm:ss}: {msg.Substring(0, Math.Min(200, msg.Length))}",
                            Severity = 6,
                            Timestamp = entry.TimeGenerated
                        });
                    }
                }
                catch { }
            }
            psLog.Close();
        }
        catch { }

        // System log — only check last 100 entries
        try
        {
            var sysLog = new EventLog("System");
            var sysCount = Math.Min(sysLog.Entries.Count, 100);
            for (int i = sysLog.Entries.Count - 1; i >= 0 && i > sysLog.Entries.Count - sysCount - 1; i--)
            {
                try
                {
                    var entry = sysLog.Entries[i];
                    if (entry.InstanceId == 7036)
                    {
                        var msg = entry.Message ?? "";
                        if (msg.Contains("SysMain", StringComparison.OrdinalIgnoreCase) ||
                            msg.Contains("Superfetch", StringComparison.OrdinalIgnoreCase))
                        {
                            if (msg.Contains("stopped", StringComparison.OrdinalIgnoreCase))
                            {
                                results.Add(new Detection
                                {
                                    Category = "Service",
                                    Name = "SysMain/Superfetch Stopped",
                                    Detail = $"SysMain service was stopped at {entry.TimeGenerated:yyyy-MM-dd HH:mm:ss} - prefetch generation disabled",
                                    Severity = 6,
                                    Timestamp = entry.TimeGenerated
                                });
                            }
                        }
                    }
                }
                catch { }
            }
            sysLog.Close();
        }
        catch { }

        return results;
    }
}
