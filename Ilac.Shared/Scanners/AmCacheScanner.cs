using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class AmCacheScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanAmCache) return results;

        // AmCache is stored in a hive file (AmCache.hve) - we need to use registry API
        // On Windows 10+, AmCache data is also accessible via registry at:
        // HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AmCache
        // But the most reliable way is to read from the hive file

        try
        {
            var amcachePath = Path.Combine(
                Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows",
                "AppCompat", "Programs", "AmCache.hve");

            if (!File.Exists(amcachePath)) return results;

            // Try to read AmCache entries from the registry
            // On Windows 10+, some AmCache data is mirrored to registry
            var regPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompat\Programs",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompat\Inventory"
            };

            foreach (var regPath in regPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regPath);
                    if (key == null) continue;

                    ScanAmCacheKey(key, results);
                }
                catch { }
            }

            // Also try CurrentUser
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Local Settings\Software\Microsoft\Windows\Shell\AmCache");
                if (key != null)
                    ScanAmCacheKey(key, results);
            }
            catch { }
        }
        catch { }

        return results;
    }

    private void ScanAmCacheKey(RegistryKey key, List<FileEntry> results, int depth = 0)
    {
        if (depth > 4) return;
        foreach (var valueName in key.GetValueNames())
        {
            try
            {
                var data = key.GetValue(valueName);
                if (data is string str && !string.IsNullOrEmpty(str))
                {
                    var lower = str.ToLower();
                    var fileName = Path.GetFileName(str);

                    string? reason = null;
                    foreach (var cheat in KnownCheats.CheatProcesses)
                    {
                        if (lower.Contains(cheat.Key.ToLower()))
                        { reason = cheat.Value; break; }
                    }
                    if (reason == null)
                    {
                        foreach (var tool in KnownCheats.SuspiciousTools)
                        {
                            if (lower.Contains(tool.Key.ToLower()))
                            { reason = tool.Value; break; }
                        }
                    }

                    if (reason != null)
                    {
                        results.Add(new FileEntry
                        {
                            Name = fileName,
                            Path = str,
                            Source = "AmCache",
                            IsSuspicious = true,
                            Reason = reason
                        });
                    }
                }
            }
            catch { }
        }

        foreach (var subKeyName in key.GetSubKeyNames())
        {
            try
            {
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey != null)
                    ScanAmCacheKey(subKey, results, depth + 1);
            }
            catch { }
        }
    }
}
