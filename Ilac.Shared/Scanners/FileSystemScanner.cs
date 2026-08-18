using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class FileSystemScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanFileSystem) return results;

        results.AddRange(ScanTempFolders(config));
        results.AddRange(ScanRecentFiles(config));

        return results;
    }

    public List<FileEntry> ScanDeleted(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanFileSystem || !config.ScanRecycleBin) return results;
        results.AddRange(ScanRecycleBin(config));
        return results;
    }

    private List<FileEntry> ScanRecycleBin(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanRecycleBin) return results;

        var cutoff = DateTime.UtcNow.AddHours(-2);

        try
        {
            var systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            if (!systemDrive.EndsWith("\\")) systemDrive += "\\";
            var recycleRoot = systemDrive + "$Recycle.Bin";

            if (!Directory.Exists(recycleRoot)) return results;

            // Get current user's SID
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;

            // Try all subdirectories
            string[] subDirs;
            try { subDirs = Directory.GetDirectories(recycleRoot); }
            catch { subDirs = Array.Empty<string>(); }

            if (subDirs.Length == 0 && sid != null)
            {
                // Fallback: directly try the current user's SID folder
                var userDir = Path.Combine(recycleRoot, sid);
                if (Directory.Exists(userDir)) subDirs = new[] { userDir };
            }

            // Also try common SIDs
            if (subDirs.Length == 0)
            {
                // Try cmd fallback to list directories
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo("cmd", $"/c dir /a /b \"{recycleRoot}\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var proc = System.Diagnostics.Process.Start(psi);
                    if (proc != null)
                    {
                        var output = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit(3000);
                        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        var expanded = new List<string>(subDirs);
                        foreach (var line in lines)
                        {
                            var fullPath = Path.Combine(recycleRoot, line.Trim());
                            if (Directory.Exists(fullPath)) expanded.Add(fullPath);
                        }
                        subDirs = expanded.ToArray();
                    }
                }
                catch { }
            }

            foreach (var recycleDir in subDirs)
            {
                try { ScanRecycleBinDirectory(recycleDir, results, cutoff); }
                catch (Exception ex)
                {
                    try { System.Diagnostics.Debug.WriteLine($"[RecycleBin] Error scanning {recycleDir}: {ex.Message}"); } catch { }
                }
            }

            // Also try the current user's SID directly (in case it wasn't found above)
            if (sid != null)
            {
                var userRecycleDir = Path.Combine(recycleRoot, sid);
                if (Directory.Exists(userRecycleDir) && !subDirs.Contains(userRecycleDir))
                {
                    try { ScanRecycleBinDirectory(userRecycleDir, results, cutoff); }
                    catch { }
                }
            }
        }
        catch { }
        return results;
    }

    private void ScanRecycleBinDirectory(string recycleDir, List<FileEntry> results, DateTime cutoff)
    {
        // Find all $I files (metadata about deleted files)
        var iFiles = new List<string>();
        try
        {
            foreach (var f in Directory.EnumerateFiles(recycleDir))
            {
                var name = Path.GetFileName(f);
                if (name.StartsWith("$I", StringComparison.OrdinalIgnoreCase))
                    iFiles.Add(f);
            }
        }
        catch { }

        try
        {
            File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_recycle_debug.log"),
                $"[{DateTime.Now:HH:mm:ss}] Dir: {recycleDir} | I-files: {iFiles.Count}\n");
        }
        catch { }

        foreach (var file in iFiles)
        {
            try
            {
                var data = File.ReadAllBytes(file);
                if (data.Length < 28) continue;

                // Parse deletion time (FILETIME) at offset 16
                DateTime? deletionTime = null;
                try
                {
                    var ft = BitConverter.ToInt64(data, 16);
                    if (ft > 0)
                        deletionTime = DateTime.FromFileTimeUtc(ft);
                }
                catch { }

                // $I file format version is byte 0 of the 8-byte header.
                // v1 (Vista/7/8): fixed 520-byte path at offset 24.
                // v2 (Win10+): int32 path length (chars) at offset 24, variable path at offset 28.
                var version = data[0];
                string originalPath;
                if (version >= 2 && data.Length >= 28)
                {
                    var pathChars = BitConverter.ToInt32(data, 24);
                    if (pathChars <= 0 || pathChars > 4096) continue;
                    var byteLen = Math.Min(pathChars * 2, data.Length - 28);
                    if (byteLen <= 0) continue;
                    var pathBytes = new byte[byteLen];
                    Array.Copy(data, 28, pathBytes, 0, byteLen);
                    originalPath = System.Text.Encoding.Unicode.GetString(pathBytes).Trim('\0');
                }
                else
                {
                    var nameBytes = new byte[Math.Min(520, data.Length - 24)];
                    Array.Copy(data, 24, nameBytes, 0, nameBytes.Length);
                    originalPath = System.Text.Encoding.Unicode.GetString(nameBytes).Trim('\0');
                }

                var fileName = Path.GetFileName(originalPath);
                if (string.IsNullOrEmpty(fileName)) continue;

                var lower = fileName.ToLower();
                var exeName = lower.EndsWith(".exe") ? lower : lower + ".exe";

                    var entry = new FileEntry
                    {
                        Name = fileName,
                        Path = originalPath,
                        Source = "Recycle Bin",
                        LastModifiedTime = deletionTime
                    };

                    bool suspicious = false;
                    bool isLegit = KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName);

                    // Check against known cheat processes
                    if (!isLegit && KnownCheats.CheatProcesses.TryGetValue(exeName, out var reason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = $"Deleted cheat file in Recycle Bin: {reason}";
                        suspicious = true;
                    }

                    // Check suspicious tools
                    if (!suspicious && !isLegit && KnownCheats.SuspiciousTools.TryGetValue(exeName, out var toolReason))
                    {
                        entry.IsSuspicious = true;
                        entry.Reason = $"Deleted suspicious tool in Recycle Bin: {toolReason}";
                        suspicious = true;
                    }

                    // Check file patterns
                    if (!suspicious && !isLegit)
                    {
                        foreach (var pattern in KnownCheats.CheatFilePatterns)
                        {
                            var matchStr = pattern.Replace("*", "").ToLower();
                            if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"Deleted file matches suspicious pattern: {pattern}";
                                suspicious = true;
                                break;
                            }
                        }
                    }

                    // Check for suspicious words in filename
                    if (!suspicious && !isLegit)
                    {
                        var suspiciousWords = new[] { "injector", "dumper", "spoofer", "bypass",
                            "executor", "loader", "cheat", "hack", "hile", "crack",
                            "keygen", "trainer", "exploit" };
                        foreach (var word in suspiciousWords)
                        {
                            if (lower.Contains(word))
                            {
                                entry.IsSuspicious = true;
                                entry.Reason = $"Deleted file contains suspicious word: '{word}'";
                                suspicious = true;
                                break;
                            }
                        }
                    }

                    // Add deleted file if within time window
                    if (deletionTime.HasValue && deletionTime.Value >= cutoff)
                    {
                        if (!suspicious)
                            entry.Reason = "Son silinen dosya (Recycle Bin)";
                        results.Add(entry);
                    }
            }
            catch { }
        }
    }

    private List<FileEntry> ScanTempFolders(ScanConfig config)
    {
        var results = new List<FileEntry>();
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "", "Temp"),
        }.Distinct();

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(tempDir, "*.exe"))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        var fileName = fi.Name;
                        var lower = fileName.ToLower();

                        // Skip legitimate files
                        if (KnownCheats.IsLegitimateFile(fileName) || KnownCheats.IsAntiCheatTool(fileName))
                            continue;

                        // Check against known cheats
                        if (KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                        {
                            results.Add(new FileEntry
                            {
                                Name = fileName,
                                Path = file,
                                Size = fi.Length,
                                CreationTime = fi.CreationTime,
                                LastModifiedTime = fi.LastWriteTime,
                                Source = "Temp Folder",
                                IsSuspicious = true,
                                Reason = reason
                            });
                        }
                        else if (KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                        {
                            results.Add(new FileEntry
                            {
                                Name = fileName,
                                Path = file,
                                Size = fi.Length,
                                CreationTime = fi.CreationTime,
                                LastModifiedTime = fi.LastWriteTime,
                                Source = "Temp Folder",
                                IsSuspicious = true,
                                Reason = toolReason
                            });
                        }
                        else if (fi.CreationTime > DateTime.Now.AddMinutes(-30))
                        {
                            // Recently created exe in temp folder - suspicious
                            results.Add(new FileEntry
                            {
                                Name = fileName,
                                Path = file,
                                Size = fi.Length,
                                CreationTime = fi.CreationTime,
                                LastModifiedTime = fi.LastWriteTime,
                                Source = "Temp Folder",
                                IsSuspicious = true,
                                Reason = "Recently created executable in temp folder"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        return results;
    }

    private List<FileEntry> ScanRecentFiles(ScanConfig config)
    {
        var results = new List<FileEntry>();
        try
        {
            var recentDir = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            if (!Directory.Exists(recentDir)) return results;

            foreach (var lnkFile in Directory.GetFiles(recentDir, "*.lnk"))
            {
                try
                {
                    var fileName = Path.GetFileNameWithoutExtension(lnkFile);
                    var lower = fileName.ToLower();

                    // Only flag known cheats and suspicious tools
                    if (KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                    {
                        results.Add(new FileEntry
                        {
                            Name = fileName,
                            Path = lnkFile,
                            Source = "Recent Files (LNK)",
                            IsSuspicious = true,
                            Reason = reason
                        });
                    }
                    else if (KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                    {
                        results.Add(new FileEntry
                        {
                            Name = fileName,
                            Path = lnkFile,
                            Source = "Recent Files (LNK)",
                            IsSuspicious = true,
                            Reason = toolReason
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        return results;
    }
}
