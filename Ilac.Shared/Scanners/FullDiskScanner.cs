using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class FullDiskScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanFileSystem) return results;

        // Scan common cheat file locations
        var scanDirs = GetScanDirectories();
        _scanStart = DateTime.Now;

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                // Scan Downloads/Desktop deeper (cheats are often in subfolders)
                var depth = (dir.Contains("Download") || dir.Contains("Desktop")) ? 2 : 2;
                ScanDirectory(dir, results, maxDepth: depth);
            }
            catch { }
        }

        // Also scan all drive roots for cheat-related folder names (depth 1 only, fast)
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable) continue;
            if (!drive.IsReady) continue;
            if (DateTime.Now - _scanStart > ScanTimeout) break;

            try
            {
                foreach (var d in Directory.GetDirectories(drive.RootDirectory.FullName))
                {
                    var lower = Path.GetFileName(d).ToLower();
                    if (lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("hile") ||
                        lower.Contains("loader") || lower.Contains("injector") || lower.Contains("spoofer") ||
                        lower.Contains("bypass") || lower.Contains("executor") || lower.Contains("mta"))
                    {
                        try { ScanDirectory(d, results, maxDepth: 1); }
                        catch { }
                    }
                }
            }
            catch { }
        }

        return results;
    }

    private List<string> GetScanDirectories()
    {
        var dirs = new List<string>();
        var userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? "";

        // Desktop + Downloads only (fast, where cheats usually are)
        dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        var downloads = Path.Combine(userProfile, "Downloads");
        dirs.Add(downloads);

        // Common cheat locations only
        dirs.Add(Path.Combine(userProfile, "Desktop", "Cheats"));
        dirs.Add(Path.Combine(userProfile, "Desktop", "Hile"));
        dirs.Add(Path.Combine(userProfile, "Downloads", "Cheats"));
        dirs.Add(Path.Combine(userProfile, "Downloads", "Hile"));

        return dirs.Distinct().Where(Directory.Exists).ToList();
    }
    private DateTime _scanStart;
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(15);

    private void ScanDirectory(string dir, List<FileEntry> results, int maxDepth, int currentDepth = 0)
    {
        if (currentDepth > maxDepth) return;
        if (results.Count > 500) return; // Safety limit
        if (DateTime.Now - _scanStart > ScanTimeout) return; // Time limit

        try
        {
            // Scan .exe files
            foreach (var file in Directory.GetFiles(dir, "*.exe"))
            {
                try
                {
                    var fi = new FileInfo(file);
                    var fileName = fi.Name;
                    var lower = fileName.ToLower();

                    // Skip legitimate files early
                    if (KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName))
                        continue;

                    var entry = new FileEntry
                    {
                        Name = fileName,
                        Path = file,
                        Size = fi.Length,
                        CreationTime = fi.CreationTime,
                        LastModifiedTime = fi.LastWriteTime,
                        Source = "Disk Scan"
                    };

                    bool suspicious = false;
                    bool isLegit = KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName);

                    // Check against known cheat processes (exact match)
                    if (!isLegit && KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = reason;
                        suspicious = true;
                    }

                    // Check suspicious tools
                    if (!suspicious && !isLegit && KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = toolReason;
                        suspicious = true;
                    }

                    // Check file patterns (cheat, hack, hile, loader, injector, etc.)
                    if (!suspicious && !isLegit)
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

                    // Check for suspicious file names with injector/dumper/spoofer etc.
                    if (!suspicious && !isLegit)
                    {
                        var suspiciousWords = new[] { "injector", "dumper", "spoofer", "bypass",
                            "executor", "loader", "cheat", "hack", "hile", "crack",
                            "keygen", "trainer", "mod menu", "exploit" };
                        foreach (var word in suspiciousWords)
                        {
                            if (lower.Contains(word))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"File name contains suspicious word: '{word}'";
                                suspicious = true;
                                break;
                            }
                        }
                    }

                    // Brand-name substring matching (catches GasMask_Lua_Executor.exe etc.)
                    if (!suspicious && !isLegit)
                    {
                        if (KnownCheats.ContainsCheatBrand(fileName))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = "Matches known cheat brand name";
                            suspicious = true;
                        }
                    }

                    if (suspicious)
                        results.Add(entry);
                }
                catch { }
            }

            // Also scan for .dll files (cheat DLLs)
            foreach (var file in Directory.GetFiles(dir, "*.dll"))
            {
                try
                {
                    var fi = new FileInfo(file);
                    var fileName = fi.Name;
                    var lower = fileName.ToLower();

                    // Skip legitimate system/app DLLs
                    if (KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName))
                        continue;

                    foreach (var pattern in KnownCheats.CheatFilePatterns)
                    {
                        var matchStr = pattern.Replace("*", "").ToLower();
                        if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                        {
                            results.Add(new FileEntry
                            {
                                Name = fileName,
                                Path = file,
                                Size = fi.Length,
                                CreationTime = fi.CreationTime,
                                LastModifiedTime = fi.LastWriteTime,
                                Source = "Disk Scan",
                                IsSuspicious = true,
                                Reason = $"Suspicious DLL matches pattern: {pattern}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }

            // Scan .lua files (cheat scripts)
            foreach (var file in Directory.GetFiles(dir, "*.lua"))
            {
                try
                {
                    var fi = new FileInfo(file);
                    var fileName = fi.Name;
                    var lower = fileName.ToLower();

                    if (lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("hile") ||
                        lower.Contains("aimbot") || lower.Contains("esp") || lower.Contains("wallhack") ||
                        lower.Contains("executor") || lower.Contains("inject"))
                    {
                        results.Add(new FileEntry
                        {
                            Name = fileName,
                            Path = file,
                            Size = fi.Length,
                            CreationTime = fi.CreationTime,
                            LastModifiedTime = fi.LastWriteTime,
                            Source = "Disk Scan",
                            IsSuspicious = true,
                            Reason = "Suspicious Lua script file"
                        });
                    }
                }
                catch { }
            }

            // Scan archive files (.rar, .zip, .7z) with cheat-related names
            var archiveExts = new[] { "*.rar", "*.zip", "*.7z" };
            foreach (var ext in archiveExts)
            {
                foreach (var file in Directory.GetFiles(dir, ext))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        var fileName = fi.Name;
                        var lower = fileName.ToLower();

                        if (KnownCheats.IsLegitimateFile(fileName)) continue;

                        bool suspicious = false;
                        string? reason = null;

                        // Check cheat brand names in archive name
                        if (KnownCheats.ContainsCheatBrand(fileName))
                        {
                            suspicious = true;
                            reason = "Archive contains known cheat brand name";
                        }

                        // Check patterns
                        if (!suspicious)
                        {
                            foreach (var pattern in KnownCheats.CheatFilePatterns)
                            {
                                var matchStr = pattern.Replace("*", "").ToLower();
                                if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                                {
                                    suspicious = true;
                                    reason = $"Archive matches suspicious pattern: {pattern}";
                                    break;
                                }
                            }
                        }

                        // Check MTA-related archive names
                        if (!suspicious && (lower.Contains("mta") || lower.Contains("gasmask") || lower.Contains("sobfox")))
                        {
                            suspicious = true;
                            reason = "Archive name references MTA cheat";
                        }

                        if (suspicious)
                        {
                            results.Add(new FileEntry
                            {
                                Name = fileName,
                                Path = file,
                                Size = fi.Length,
                                CreationTime = fi.CreationTime,
                                LastModifiedTime = fi.LastWriteTime,
                                Source = "Disk Scan (Archive)",
                                IsSuspicious = true,
                                Reason = reason ?? "Suspicious archive"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Recurse into subdirectories
        if (currentDepth < maxDepth)
        {
            try
            {
                foreach (var subDir in Directory.GetDirectories(dir))
                {
                    var dirName = Path.GetFileName(subDir).ToLower();

                    // Skip system directories (where legitimate system DLLs live)
                    if (dirName == "windows" || dirName == "system32" || dirName == "syswow64" ||
                        dirName == "winsxs" || dirName == "assembly" || dirName == "installer" ||
                        dirName == "servicing" || dirName == "driverstore" || dirName == "diagtrack" ||
                        dirName == "microsoft" || dirName == "common files" || dirName == "windowsapps" ||
                        dirName == "packages" || dirName == "cache" || dirName == "fonts" ||
                        dirName == "temp" && currentDepth > 0)
                        continue;

                    ScanDirectory(subDir, results, maxDepth, currentDepth + 1);
                }
            }
            catch { }
        }
    }
}
