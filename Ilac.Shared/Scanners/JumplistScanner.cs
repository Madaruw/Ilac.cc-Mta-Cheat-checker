using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class JumplistScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanJumplists) return results;

        try
        {
            // Automatic Destinations
            var autoDestDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "AutomaticDestinations");

            if (Directory.Exists(autoDestDir))
            {
                foreach (var file in Directory.GetFiles(autoDestDir, "*.automaticDestinations-ms"))
                {
                    try
                    {
                        // These are OLE compound files - read as binary and search for paths
                        var data = File.ReadAllBytes(file);
                        var text = System.Text.Encoding.Unicode.GetString(data);
                        var lower = text.ToLower();

                        // Check for cheat-related file names in the jumplist data
                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            var cheatKey = cheat.Key.ToLower();
                            if (lower.Contains(cheatKey))
                            {
                                var fileName = Path.GetFileName(file);
                                // Try to extract a more specific path
                                var idx = lower.IndexOf(cheatKey);
                                var contextStart = Math.Max(0, idx - 100);
                                var contextLen = Math.Min(300, lower.Length - contextStart);
                                var context = text.Substring(contextStart, contextLen);

                                results.Add(new FileEntry
                                {
                                    Name = cheat.Key,
                                    Path = context.Trim('\0'),
                                    Source = "Jumplist",
                                    IsSuspicious = true,
                                    Reason = $"Jumplist references known cheat: {cheat.Value}",
                                    LastModifiedTime = File.GetLastWriteTime(file)
                                });
                                break;
                            }
                        }

                        foreach (var tool in KnownCheats.SuspiciousTools)
                        {
                            var toolKey = tool.Key.ToLower();
                            if (lower.Contains(toolKey))
                            {
                                var fileName = Path.GetFileName(file);
                                results.Add(new FileEntry
                                {
                                    Name = tool.Key,
                                    Path = file,
                                    Source = "Jumplist",
                                    IsSuspicious = true,
                                    Reason = $"Jumplist references suspicious tool: {tool.Value}",
                                    LastModifiedTime = File.GetLastWriteTime(file)
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }

            // Custom Destinations
            var customDestDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "CustomDestinations");

            if (Directory.Exists(customDestDir))
            {
                foreach (var file in Directory.GetFiles(customDestDir, "*.customDestinations-ms"))
                {
                    try
                    {
                        var data = File.ReadAllBytes(file);
                        var text = System.Text.Encoding.Unicode.GetString(data);
                        var lower = text.ToLower();

                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            if (lower.Contains(cheat.Key.ToLower()))
                            {
                                results.Add(new FileEntry
                                {
                                    Name = cheat.Key,
                                    Path = file,
                                    Source = "Custom Jumplist",
                                    IsSuspicious = true,
                                    Reason = $"Custom jumplist references known cheat: {cheat.Value}",
                                    LastModifiedTime = File.GetLastWriteTime(file)
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        return results;
    }
}
