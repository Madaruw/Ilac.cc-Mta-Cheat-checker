using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class YARAScanner
{
    private static readonly List<YaraRule> BuiltInRules = new()
    {
        new YaraRule
        {
            Name = "CheatEngine_Detect",
            Description = "Detects Cheat Engine related strings",
            Patterns = new[] { "cheatengine", "CE_", "speedhack", "dbvm", "windows_hook" }
        },
        new YaraRule
        {
            Name = "VMProtect_Detect",
            Description = "Detects VMProtect packed executables",
            Patterns = new[] { "vmp0", "vmp1", "vmp2", "VMProtect", "!VMP" }
        },
        new YaraRule
        {
            Name = "Themida_Detect",
            Description = "Detects Themida/WinLicense packed files",
            Patterns = new[] { "themida", "winlicense", "!TMD", "!WL" }
        },
        new YaraRule
        {
            Name = "AutoHotkey_Compiled",
            Description = "Detects compiled AutoHotkey scripts",
            Patterns = new[] { "AutoHotkey", ">AUTOHOTKEY", "AHK" }
        },
        new YaraRule
        {
            Name = "ProcessHacker_Driver",
            Description = "Detects Process Hacker kernel driver",
            Patterns = new[] { "kprocesshacker", "processhacker", "KPH_" }
        },
        new YaraRule
        {
            Name = "MTA_Cheat_Loader",
            Description = "Detects common MTA cheat loader patterns",
            Patterns = new[] { "gasmask", "nexus_mta", "0xcheat", "capyprivate", "exterium" }
        },
        new YaraRule
        {
            Name = "KeyAuth_Client",
            Description = "Detects KeyAuth authentication strings",
            Patterns = new[] { "keyauth", "KeyAuth", "sessionid", "ownerid", "appname" }
        },
        new YaraRule
        {
            Name = "DMA_Firmware",
            Description = "Detects DMA cheat firmware patterns",
            Patterns = new[] { "PCILeech", "DMA", "fpga", "screamer", "acq" }
        },
        new YaraRule
        {
            Name = "ReflectiveLoader",
            Description = "Detects reflective DLL loading patterns",
            Patterns = new[] { "ReflectiveLoader", "reflective", "RWX", "NtCreateSection" }
        },
        new YaraRule
        {
            Name = "Memory_Mapper",
            Description = "Detects kernel memory mapper patterns",
            Patterns = new[] { "kdmapper", "mapper", "mapdriver", "EaseMapper", "TurboMapper" }
        },
    };

    public List<Detection> ScanFile(ScanConfig config, string filePath)
    {
        var results = new List<Detection>();
        if (!File.Exists(filePath)) return results;

        try
        {
            var content = File.ReadAllText(filePath);
            var lowerContent = content.ToLower();

            foreach (var rule in BuiltInRules)
            {
                foreach (var pattern in rule.Patterns)
                {
                    if (lowerContent.Contains(pattern.ToLower()))
                    {
                        results.Add(new Detection
                        {
                            Category = "YARA",
                            Name = $"YARA Match: {rule.Name}",
                            Detail = $"{rule.Description} - Pattern: {pattern}",
                            Severity = 7
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return results;
    }

    public List<Detection> ScanMemory(ScanConfig config, byte[] memory)
    {
        var results = new List<Detection>();
        if (memory == null || memory.Length == 0) return results;

        try
        {
            var text = System.Text.Encoding.ASCII.GetString(memory);
            var lowerText = text.ToLower();

            foreach (var rule in BuiltInRules)
            {
                foreach (var pattern in rule.Patterns)
                {
                    if (lowerText.Contains(pattern.ToLower()))
                    {
                        results.Add(new Detection
                        {
                            Category = "YARA",
                            Name = $"YARA Memory Match: {rule.Name}",
                            Detail = $"{rule.Description} - Found in memory",
                            Severity = 8
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return results;
    }

    private class YaraRule
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string[] Patterns { get; set; } = Array.Empty<string>();
    }
}
