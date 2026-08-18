using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class HostsFileScanner
{
    private static readonly string HostsPath = Path.Combine(
        Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows",
        "System32", "drivers", "etc", "hosts");

    // Game and anti-cheat domains that should NOT be blocked
    private static readonly string[] ProtectedDomains = new[]
    {
        "multitheftauto.com", "mtasa.com", "forum.mtasa.com",
        "update.multitheftauto.com", "nightly.multitheftauto.com",
        "rockstargames.com", "socialclub.rockstargames.com",
        "fairplay.com", "fairplay.mtasa.com",
        "fivem.net", "fivem.gg", "redm.gg",
        "rage.mp", "altv.mp",
        "keyauth.cc", "keyauth.com",
        "napse.ac", "anticheat.ac", "detect.ac",
        "siles.ac", "echo.ac", "abbys-ac",
        "steam.com", "steampowered.com",
        "discord.com", "discordapp.com",
        "epicgames.com",
    };

    public List<Detection> Scan(ScanConfig config)
    {
        var results = new List<Detection>();
        if (!config.ScanHostsFile) return results;

        try
        {
            if (!File.Exists(HostsPath)) return results;

            var lines = File.ReadAllLines(HostsPath);
            var modifiedTime = File.GetLastWriteTime(HostsPath);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#")) continue;

                // Skip default localhost entries
                if (trimmed.Contains("localhost")) continue;

                var lower = trimmed.ToLower();

                // Check if any protected domain is being blocked
                foreach (var domain in ProtectedDomains)
                {
                    if (lower.Contains(domain))
                    {
                        // Check if it's being redirected to localhost (blocked)
                        if (lower.Contains("127.0.0.1") || lower.Contains("0.0.0.0"))
                        {
                            results.Add(new Detection
                            {
                                Category = "Hosts File",
                                Name = $"Domain Blocked: {domain}",
                                Detail = $"Hosts file redirects {domain} to 127.0.0.1 or 0.0.0.0 - game/AC server blocked. Line: {trimmed}",
                                Severity = 8
                            });
                        }
                    }
                }

                // Flag any non-standard entry that's not localhost
                if (!lower.Contains("localhost") && !lower.Contains("::1") &&
                    (lower.Contains("127.0.0.1") || lower.Contains("0.0.0.0")))
                {
                    // Only flag if it's not a well-known blocking entry
                    var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        var blockedDomain = parts[1];
                        // Skip if it's in protected domains (already flagged above)
                        var isProtected = ProtectedDomains.Any(d =>
                            blockedDomain.Contains(d, StringComparison.OrdinalIgnoreCase));

                        if (!isProtected && !results.Any(r => r.Detail.Contains(blockedDomain)))
                        {
                            results.Add(new Detection
                            {
                                Category = "Hosts File",
                                Name = "Non-standard Hosts Entry",
                                Detail = $"Hosts file contains non-standard entry: {trimmed} (modified: {modifiedTime:yyyy-MM-dd HH:mm})",
                                Severity = 3
                            });
                        }
                    }
                }
            }
        }
        catch { }

        return results;
    }
}
