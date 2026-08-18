using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class RegistryScanner
{
    public List<RegistryEntry> Scan(ScanConfig config)
    {
        var results = new List<RegistryEntry>();
        if (!config.ScanRegistry) return results;

        results.AddRange(ScanRunKeys());
        results.AddRange(ScanUserAssist());
        results.AddRange(ScanMRU());

        return results;
    }

    private List<RegistryEntry> ScanRunKeys()
    {
        var results = new List<RegistryEntry>();
        var runKeyPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var keyPath in runKeyPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    var entry = new RegistryEntry
                    {
                        Key = $"HKLM\\{keyPath}",
                        Value = valueName,
                        Data = value
                    };

                    var lower = value.ToLower();

                    // Use exact process name matching, not substring
                    foreach (var cheat in KnownCheats.CheatProcesses)
                    {
                        var cheatKey = cheat.Key.ToLower();
                        // Match if the value contains the exact exe name
                        if (lower.Contains(cheatKey))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = $"Startup entry matches known cheat: {cheat.Value}";
                            break;
                        }
                    }

                    if (!entry.IsSuspicious)
                    {
                        foreach (var tool in KnownCheats.SuspiciousTools)
                        {
                            if (lower.Contains(tool.Key.ToLower()))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"Startup entry matches suspicious tool: {tool.Value}";
                                break;
                            }
                        }
                    }

                    results.Add(entry);
                }
            }
            catch { }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            if (key != null)
            {
                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    var entry = new RegistryEntry
                    {
                        Key = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        Value = valueName,
                        Data = value
                    };

                    var lower = value.ToLower();
                    foreach (var cheat in KnownCheats.CheatProcesses)
                    {
                        if (lower.Contains(cheat.Key.ToLower()))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = $"Startup entry matches known cheat: {cheat.Value}";
                            break;
                        }
                    }

                    if (!entry.IsSuspicious)
                    {
                        foreach (var tool in KnownCheats.SuspiciousTools)
                        {
                            if (lower.Contains(tool.Key.ToLower()))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"Startup entry matches suspicious tool: {tool.Value}";
                                break;
                            }
                        }
                    }

                    results.Add(entry);
                }
            }
        }
        catch { }

        return results;
    }

    private List<RegistryEntry> ScanUserAssist()
    {
        var results = new List<RegistryEntry>();
        try
        {
            var path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) return results;

            foreach (var guidKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var guidKey = key.OpenSubKey(guidKeyName);
                    if (guidKey == null) continue;

                    using var countKey = guidKey.OpenSubKey("Count");
                    if (countKey == null) continue;

                    foreach (var valueName in countKey.GetValueNames())
                    {
                        try
                        {
                            var data = countKey.GetValue(valueName);
                            if (data is byte[] bytes && bytes.Length > 0)
                            {
                                var decodedName = DecodeROT13(valueName);
                                if (string.IsNullOrEmpty(decodedName)) continue;

                                var lower = decodedName.ToLower();
                                var fileName = Path.GetFileName(lower);

                                // Use exact exe name matching
                                var entry = new RegistryEntry
                                {
                                    Key = $"HKCU\\{path}\\{guidKeyName}\\Count",
                                    Value = decodedName,
                                    Data = $"Last executed: {DecodeExecutionTime(bytes)}"
                                };

                                // Check cheat processes with exact file name match
                                foreach (var cheat in KnownCheats.CheatProcesses)
                                {
                                    var cheatKey = cheat.Key.ToLower();
                                    if (fileName == cheatKey || lower.EndsWith("\\" + cheatKey))
                                    {
                                        entry.IsSuspicious = true;
                                        entry.Reason = $"UserAssist entry matches known cheat: {cheat.Value}";
                                        break;
                                    }
                                }

                                if (!entry.IsSuspicious)
                                {
                                    foreach (var tool in KnownCheats.SuspiciousTools)
                                    {
                                        if (fileName == tool.Key.ToLower() || lower.EndsWith("\\" + tool.Key.ToLower()))
                                        {
                                            entry.IsSuspicious = true;
                                            entry.Reason = $"UserAssist entry matches suspicious tool: {tool.Value}";
                                            break;
                                        }
                                    }
                                }

                                // Only add suspicious entries
                                if (entry.IsSuspicious)
                                    results.Add(entry);
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

    private List<RegistryEntry> ScanMRU()
    {
        var results = new List<RegistryEntry>();
        try
        {
            var mruPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            };

            foreach (var mruPath in mruPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(mruPath);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (valueName == "MRUListEx") continue;
                        var value = key.GetValue(valueName)?.ToString() ?? "";

                        var entry = new RegistryEntry
                        {
                            Key = $"HKCU\\{mruPath}",
                            Value = valueName,
                            Data = value
                        };

                        var lower = value.ToLower();

                        // Only flag if it contains an actual cheat exe name
                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            if (lower.Contains(cheat.Key.ToLower()))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"MRU entry matches known cheat: {cheat.Value}";
                                break;
                            }
                        }

                        if (entry.IsSuspicious)
                            results.Add(entry);
                    }
                }
                catch { }
            }
        }
        catch { }
        return results;
    }

    private static string DecodeROT13(string input)
    {
        try
        {
            var chars = input.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                if (chars[i] >= 'a' && chars[i] <= 'z')
                    chars[i] = (char)((chars[i] - 'a' + 13) % 26 + 'a');
                else if (chars[i] >= 'A' && chars[i] <= 'Z')
                    chars[i] = (char)((chars[i] - 'A' + 13) % 26 + 'A');
            }
            return new string(chars);
        }
        catch { return input; }
    }

    private static string DecodeExecutionTime(byte[] data)
    {
        try
        {
            if (data.Length >= 16)
            {
                long fileTime = BitConverter.ToInt64(data, 8);
                if (fileTime > 0 && fileTime < 999999999999999999)
                {
                    var dt = DateTime.FromFileTime(fileTime);
                    return dt.ToString("yyyy-MM-dd HH:mm:ss");
                }
            }
        }
        catch { }
        return "Unknown";
    }
}
