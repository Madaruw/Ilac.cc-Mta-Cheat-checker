using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class BAMScanner
{
    private static readonly string[] BamBasePaths =
    {
        @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        @"SYSTEM\CurrentControlSet\Services\bam\State\Settings"
    };

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanBAM) return results;

        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            if (sid == null) return results;

            foreach (var basePath in BamBasePaths)
            {
                try
                {
                    using var parentKey = Registry.LocalMachine.OpenSubKey(basePath);
                    if (parentKey == null) continue;

                    // Try current user SID subkey
                    var sidKeyPath = sid;
                    using var sidKey = parentKey.OpenSubKey(sidKeyPath);
                    if (sidKey != null)
                    {
                        results.AddRange(ScanBamKey(sidKey, "BAM"));
                    }

                    // Also scan all user SIDs (for multi-user systems)
                    foreach (var subKeyName in parentKey.GetSubKeyNames())
                    {
                        if (subKeyName == sid) continue;
                        try
                        {
                            using var subKey = parentKey.OpenSubKey(subKeyName);
                            if (subKey != null)
                            {
                                results.AddRange(ScanBamKey(subKey, "BAM"));
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    private List<FileEntry> ScanBamKey(RegistryKey key, string source)
    {
        var results = new List<FileEntry>();

        foreach (var valueName in key.GetValueNames())
        {
            try
            {
                // The VALUE NAME is the file path in BAM
                // Format: \Device\HarddiskVolume4\Windows\System32\notepad.exe
                // Or:    \Device\HarddiskVolume1\Users\...\cheat.exe
                var filePath = valueName;

                if (string.IsNullOrEmpty(filePath)) continue;

                // Convert device path to drive letter
                filePath = ConvertDevicePathToDrivePath(filePath);

                if (string.IsNullOrEmpty(filePath)) continue;

                // Get timestamp from value data
                var data = key.GetValue(valueName);
                DateTime? execTime = null;
                if (data is byte[] bytes && bytes.Length >= 8)
                {
                    try
                    {
                        long timestamp = BitConverter.ToInt64(bytes, 0);
                        if (timestamp > 0)
                            execTime = DateTime.FromFileTimeUtc(timestamp);
                    }
                    catch { }
                }

                var fileName = Path.GetFileName(filePath);
                if (string.IsNullOrEmpty(fileName)) continue;

                var entry = new FileEntry
                {
                    Name = fileName,
                    Path = filePath,
                    LastExecutionTime = execTime,
                    Source = source
                };

                var lower = fileName.ToLower();
                bool isLegit = KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName);

                // Only mark as suspicious if it matches a known cheat process
                if (!isLegit && KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                {
                    entry.IsSuspicious = true;
                    entry.Reason = reason;
                }
                else if (!isLegit && KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                {
                    entry.IsSuspicious = true;
                    entry.Reason = toolReason;
                }
                else if (!isLegit)
                {
                    foreach (var pattern in KnownCheats.CheatFilePatterns)
                    {
                        var matchStr = pattern.Replace("*", "").ToLower();
                        if (lower.Contains(matchStr))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = $"Matches suspicious pattern: {pattern}";
                            break;
                        }
                    }
                }

                // Only add to results if it's suspicious
                if (entry.IsSuspicious)
                    results.Add(entry);
            }
            catch { }
        }

        return results;
    }

    private static string ConvertDevicePathToDrivePath(string devicePath)
    {
        try
        {
            if (string.IsNullOrEmpty(devicePath)) return "";

            // \Device\HarddiskVolumeN\... -> map to the real drive letter via QueryDosDevice
            if (devicePath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                var rest = devicePath.Substring(@"\Device\".Length);
                var slash = rest.IndexOf('\\');
                var volumePart = slash < 0 ? rest : rest.Substring(0, slash);
                var remainder = slash < 0 ? "" : rest.Substring(slash);
                var deviceKey = @"\Device\" + volumePart;

                var map = NativeMethods.GetDeviceToDriveMap();
                foreach (var (device, letter) in map)
                {
                    if (string.Equals(device, deviceKey, StringComparison.OrdinalIgnoreCase))
                        return letter + ":" + remainder;
                }

                // Fall back: try the raw volume path against any mapped device (handles shadow copies etc.)
                foreach (var (device, letter) in map)
                {
                    if (devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                        return letter + ":" + devicePath.Substring(device.Length);
                }
                return "";
            }

            // \??\C:\... style
            if (devicePath.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                return devicePath.Substring(4);

            // Already a drive path
            if (devicePath.Length >= 2 && devicePath[1] == ':')
                return devicePath;

            return "";
        }
        catch { return ""; }
    }

    public bool IsBAMTampered()
    {
        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            if (sid == null) return false;

            bool anyKeyExists = false;

            foreach (var basePath in BamBasePaths)
            {
                try
                {
                    using var parentKey = Registry.LocalMachine.OpenSubKey(basePath);
                    if (parentKey == null) continue;

                    // Check if parent key exists (BAM service is registered)
                    anyKeyExists = true;

                    // Check for current user's SID
                    using var sidKey = parentKey.OpenSubKey(sid);
                    if (sidKey != null)
                    {
                        var values = sidKey.GetValueNames();
                        if (values.Length > 0)
                            return false; // BAM has entries, not tampered
                    }

                    // Check other user SIDs
                    foreach (var subKeyName in parentKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = parentKey.OpenSubKey(subKeyName);
                            if (subKey != null && subKey.GetValueNames().Length > 0)
                                return false;
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // If BAM registry base path doesn't exist at all, it's not necessarily tampered
            // On some Windows builds BAM may not be enabled
            if (!anyKeyExists) return false;

            // Base key exists but no user entries - could be tampered
            return true;
        }
        catch { return false; }
    }
}
