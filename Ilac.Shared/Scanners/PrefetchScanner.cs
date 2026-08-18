using System.Diagnostics;
using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class PrefetchScanner
{
    private static readonly string PrefetchDir = Path.Combine(
        Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows", "Prefetch");

    public List<string> GetRecentFiles(int minutesBack)
    {
        var results = new List<string>();

        if (!IsPrefetchEnabled()) return results;
        if (!Directory.Exists(PrefetchDir)) return results;

        var cutoff = DateTime.Now.AddMinutes(-minutesBack);
        try
        {
            foreach (var pfFile in Directory.GetFiles(PrefetchDir, "*.pf"))
            {
                try
                {
                    var modified = File.GetLastWriteTime(pfFile);
                    if (modified >= cutoff)
                    {
                        var name = Path.GetFileNameWithoutExtension(pfFile);
                        if (name.EndsWith("-", StringComparison.OrdinalIgnoreCase))
                            name = name[..^1];
                        results.Add(name);
                    }
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanPrefetch) return results;

        if (!IsPrefetchEnabled()) return results;
        if (!Directory.Exists(PrefetchDir)) return results;

        var recentCutoff = DateTime.Now.AddMinutes(-Math.Max(1, config.PrefetchTimeMinutes));

        try
        {
            foreach (var pfFile in Directory.GetFiles(PrefetchDir, "*.pf"))
            {
                try
                {
                    var fi = new FileInfo(pfFile);
                    var rawName = Path.GetFileNameWithoutExtension(pfFile);

                    // Prefetch files are named <EXENAME>-<HASH>.pf; recover the real exe name
                    // by cutting at the LAST hyphen.
                    var exeName = rawName;
                    var lastDash = rawName.LastIndexOf('-');
                    if (lastDash > 0)
                        exeName = rawName.Substring(0, lastDash);
                    if (string.IsNullOrEmpty(exeName)) continue;

                    var fullExeName = exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                        ? exeName : exeName + ".exe";
                    var lower = fullExeName.ToLower();

                    var entry = new FileEntry
                    {
                        Name = fullExeName,
                        Path = pfFile,
                        LastExecutionTime = fi.LastWriteTime,
                        LastModifiedTime = fi.LastWriteTime,
                        Source = "Prefetch"
                    };

                    bool suspicious = false;
                    bool isLegit = KnownCheats.IsLegitimateFile(fullExeName) || KnownCheats.IsAntiCheatTool(fullExeName);
                    if (!isLegit && KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = reason;
                        suspicious = true;
                    }
                    else if (!isLegit && KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = toolReason;
                        suspicious = true;
                    }
                    else if (!isLegit)
                    {
                        foreach (var pattern in KnownCheats.CheatFilePatterns)
                        {
                            var matchStr = pattern.Replace("*", "").ToLower();
                            if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"Matches suspicious pattern: {pattern}";
                                suspicious = true;
                                break;
                            }
                        }
                    }

                    // Report cheat matches regardless of when they ran (a cheat that ran
                    // 3 hours ago still matters). Non-matches only surface if they ran
                    // inside the configured time window as a forensic "recent activity" note.
                    if (suspicious)
                        results.Add(entry);
                    else if (fi.LastWriteTime >= recentCutoff && fullExeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        entry.Reason = "Recently executed program";
                        results.Add(entry);
                    }
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    public bool IsPrefetchDeleted()
    {
        try
        {
            if (!IsPrefetchEnabled()) return false;
            if (!Directory.Exists(PrefetchDir)) return false;
            var files = Directory.GetFiles(PrefetchDir, "*.pf");
            return files.Length == 0;
        }
        catch { return false; }
    }

    private bool IsPrefetchEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (key == null) return true;

            var enablePrefetch = key.GetValue("EnablePrefetch");
            if (enablePrefetch != null)
            {
                var val = Convert.ToInt32(enablePrefetch);
                return val != 0;
            }
            return true;
        }
        catch { return true; }
    }
}
