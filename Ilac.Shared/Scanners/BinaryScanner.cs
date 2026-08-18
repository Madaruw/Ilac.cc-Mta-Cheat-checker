using System.Text;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class BinaryScanner
{
    // Only REAL cheat-specific strings — not generic Lua functions or MTA game name
    private static readonly string[] CheatSpecificStrings =
    {
        "gasmask", "GasMaskAgent", "NeutrinoInjector",
        "sobfox", "nexida", "deadlyteam", "Deadly Team",
        "exterium", "capyprivate", "0xcheat", "shine menu",
        "hydrogenmenu", "franny", "speedi", "mtasacheats",
        "SimpleInjectorMTA", "SAModInjector", "mtaspoofer",
        "superspoofer", "ntkernelMC", "FairplayKD bypass",
        "R.I.P FairplayKD", "boxyhax", "mtahook",
        "eclipso.cc", "phantomcheat", "scriptware",
        "crespo.gg", "wiizard.gg", "keyauth.cc",
        "unknowncheats.me", "hackvshack.net",
    };

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        return results;
    }

    public List<FileEntry> ScanSuspiciousFiles(List<FileEntry> suspiciousFiles, ScanConfig config)
    {
        var results = new List<FileEntry>();

        foreach (var file in suspiciousFiles.Where(f => f.IsSuspicious).Take(10))
        {
            try
            {
                if (!File.Exists(file.Path)) continue;
                var ext = Path.GetExtension(file.Path).ToLower();
                if (ext != ".exe" && ext != ".dll") continue;

                // Skip legitimate files
                if (KnownCheats.IsLegitimateFile(file.Name)) continue;
                if (KnownCheats.IsAntiCheatTool(file.Name)) continue;

                // Skip files loaded into MTA process (they're MTA's own modules)
                if ((file.Source ?? "").Contains("Loaded Module", StringComparison.OrdinalIgnoreCase))
                    continue;

                var content = File.ReadAllBytes(file.Path);
                if (content.Length == 0 || content.Length > 5_000_000) continue; // 5MB max

                var text = (Encoding.ASCII.GetString(content) + " " +
                            Encoding.Unicode.GetString(content)).ToLower();

                var foundKeywords = new List<string>();
                foreach (var keyword in CheatSpecificStrings)
                {
                    if (text.Contains(keyword.ToLower()))
                        foundKeywords.Add(keyword);
                }

                // Require at least 2 matches to reduce false positives
                if (foundKeywords.Count >= 2)
                {
                    var topKeywords = foundKeywords.Distinct().Take(5).ToList();
                    results.Add(new FileEntry
                    {
                        Name = file.Name,
                        Path = file.Path,
                        Source = "Binary Scan",
                        IsSuspicious = true,
                        Reason = $"Hex analiz: icerisinde {foundKeywords.Count} hile string'i bulundu: {string.Join(", ", topKeywords)}"
                    });
                }
            }
            catch { }
        }

        return results;
    }
}
