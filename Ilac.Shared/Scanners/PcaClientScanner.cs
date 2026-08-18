using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class PcaClientScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanPcaClient) return results;

        try
        {
            // PcaClient stores recently opened executables
            // HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
            // Also check LastVisitedPidlMRU
            var regPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            };

            foreach (var regPath in regPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regPath);
                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            foreach (var valueName in subKey.GetValueNames())
                            {
                                if (valueName == "MRUListEx") continue;

                                try
                                {
                                    var data = subKey.GetValue(valueName);
                                    if (data is byte[] bytes)
                                    {
                                        // Parse the MRU data - it contains a PIDL which has the file path
                                        var path = ExtractPathFromPidl(bytes);
                                        if (!string.IsNullOrEmpty(path))
                                        {
                                            var fileName = Path.GetFileName(path);
                                            var lower = fileName.ToLower();

                                            var entry = new FileEntry
                                            {
                                                Name = fileName,
                                                Path = path,
                                                Source = "PcaClient/OpenSaveMRU"
                                            };

                                            if (KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                                            {
                                                entry.IsSuspicious = true;
                                                entry.Reason = reason;
                                                results.Add(entry);
                                            }
                                            else if (KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                                            {
                                                entry.IsSuspicious = true;
                                                entry.Reason = toolReason;
                                                results.Add(entry);
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Also check PcaSvc recent applications
            // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\PCASession
            try
            {
                using var pcaKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\PCASession");
                if (pcaKey != null)
                {
                    foreach (var valueName in pcaKey.GetValueNames())
                    {
                        var value = pcaKey.GetValue(valueName)?.ToString() ?? "";
                        var lower = value.ToLower();

                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            if (lower.Contains(cheat.Key.ToLower()))
                            {
                                results.Add(new FileEntry
                                {
                                    Name = Path.GetFileName(value),
                                    Path = value,
                                    Source = "PcaClient",
                                    IsSuspicious = true,
                                    Reason = $"PcaClient entry: {cheat.Value}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
        }
        catch { }

        return results;
    }

    private string ExtractPathFromPidl(byte[] data)
    {
        try
        {
            // PIDLs are complex binary structures, but file paths are often stored as Unicode strings
            var text = System.Text.Encoding.Unicode.GetString(data);
            // Find a path-like pattern (contains backslash and colon)
            var match = System.Text.RegularExpressions.Regex.Match(text,
                @"[A-Za-z]:\\[^\x00]+");
            return match.Success ? match.Value.TrimEnd('\0') : "";
        }
        catch { return ""; }
    }
}
