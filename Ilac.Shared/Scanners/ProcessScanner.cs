using System.Diagnostics;
using System.Management;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class ProcessScanner
{
    public List<ProcessEntry> Scan(ScanConfig config)
    {
        var results = new List<ProcessEntry>();
        if (!config.ScanProcesses) return results;

        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    var procName = proc.ProcessName + ".exe";

                    // Skip system processes
                    if (KnownCheats.IsSystemProcess(procName)) continue;

                    var entry = new ProcessEntry
                    {
                        ProcessName = procName,
                        PID = proc.Id,
                        WindowTitle = proc.MainWindowTitle ?? ""
                    };

                    bool isSuspicious = false;

                    // Check against cheat processes (high severity)
                    if (KnownCheats.CheatProcesses.TryGetValue(procName.ToLower(), out var reason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = reason;
                        isSuspicious = true;
                    }

                    // Check against suspicious tools (lower severity)
                    if (!isSuspicious && KnownCheats.SuspiciousTools.TryGetValue(procName.ToLower(), out var toolReason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = toolReason;
                        isSuspicious = true;
                    }

                    // Only check path for suspicious processes (WMI is slow)
                    if (isSuspicious)
                    {
                        try
                        {
                            var path = GetProcessPath(proc.Id);
                            if (!string.IsNullOrEmpty(path) && IsSuspiciousPath(path))
                            {
                                entry.Reason = $"Running from suspicious path: {path}";
                            }
                        }
                        catch { }
                    }

                    // Only add suspicious processes to results
                    if (isSuspicious)
                        results.Add(entry);
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    private static string? GetParentProcess(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                try
                {
                    var parent = Process.GetProcessById(parentPid);
                    return parent.ProcessName;
                }
                catch { return null; }
            }
        }
        catch { }
        return null;
    }

    private static string? GetProcessPath(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (var obj in searcher.Get())
            {
                return obj["ExecutablePath"]?.ToString();
            }
        }
        catch { }
        return null;
    }

    private static bool IsSuspiciousPath(string path)
    {
        var lower = path.ToLower();
        if (lower.Contains(@"\temp\")) return true;
        if (lower.Contains(@"\tmp\")) return true;
        if (lower.Contains(@"\downloads\")) return false;
        if (lower.Contains(@"\appdata\local\temp\")) return true;
        if (lower.Contains(@"\programdata\")) return false;
        if (lower.StartsWith(@"\\?\") || lower.StartsWith(@"\??\")) return true;
        return false;
    }

    public static bool IsVpnProcess(string processName)
    {
        var lower = processName.ToLower();
        return KnownCheats.VPNProcessNames.Any(vpn =>
            lower.Contains(vpn.ToLower()));
    }
}
