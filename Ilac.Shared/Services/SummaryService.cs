using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Services;

public class SummaryService
{
    private readonly ScoringService _scoring = new();

    public Summary GenerateSummary(ScanResult result)
    {
        var summary = new Summary();

        // Only count actually suspicious files
        var suspiciousFiles = result.SuspiciousFiles
            .Where(f => f.IsSuspicious && !string.IsNullOrEmpty(f.Name))
            .GroupBy(f => f.Name.ToLower())
            .Select(g => g.First())
            .ToList();

        foreach (var file in suspiciousFiles)
        {
            var fileName = file.Name.ToLower();

            if (KnownCheats.CheatProcesses.TryGetValue(fileName, out var explanation))
            {
                summary.FileExplanations[file.Name] = explanation;
                if (!summary.FoundCheatNames.Contains(file.Name))
                    summary.FoundCheatNames.Add(file.Name);
            }
            else if (KnownCheats.SuspiciousTools.TryGetValue(fileName, out var toolExplanation))
            {
                summary.FileExplanations[file.Name] = toolExplanation;
                if (!summary.FoundCheatNames.Contains(file.Name))
                    summary.FoundCheatNames.Add(file.Name);
            }
            else
            {
                summary.FileExplanations[file.Name] = $"Suspicious file found: {file.Reason}";
                if (!summary.FoundCheatNames.Contains(file.Name))
                    summary.FoundCheatNames.Add(file.Name);
            }

            var category = CategorizeCheat(file.Name, file.Reason);
            if (category != null && !summary.FoundCategories.Contains(category))
                summary.FoundCategories.Add(category);
        }

        // Only count actually suspicious processes
        foreach (var proc in result.SuspiciousProcesses.Where(p => p.IsSuspicious))
        {
            if (!string.IsNullOrEmpty(proc.ProcessName))
            {
                if (!summary.FoundCheatNames.Contains(proc.ProcessName))
                    summary.FoundCheatNames.Add(proc.ProcessName);

                var category = CategorizeCheat(proc.ProcessName, proc.Reason);
                if (category != null && !summary.FoundCategories.Contains(category))
                    summary.FoundCategories.Add(category);
            }
        }

        foreach (var bh in result.BrowserHistory)
        {
            if (!string.IsNullOrEmpty(bh.MatchReason))
            {
                // Browser hits are shown in their own embed section; do not dump raw
                // URLs into the cheat-name list (they bloat the field past Discord limits).
                var category = CategorizeSearch(bh);
                if (category != null && !summary.FoundCategories.Contains(category))
                    summary.FoundCategories.Add(category);
            }
        }

        summary.TotalDetections = result.BrowserHistory.Count +
                                   result.SuspiciousProcesses.Count(p => p.IsSuspicious) +
                                   result.SuspiciousFiles.Count(f => f.IsSuspicious) +
                                   result.DeletedFiles.Count(f => f.IsSuspicious) +
                                   result.BypassAttempts.Count +
                                   result.Detections.Count;

        summary.HighSeverityCount = result.BypassAttempts.Count(b => b.Severity >= 8) +
                                     result.Detections.Count(d => d.Severity >= 8);

        summary.MediumSeverityCount = result.BypassAttempts.Count(b => b.Severity >= 5 && b.Severity < 8) +
                                       result.Detections.Count(d => d.Severity >= 5 && d.Severity < 8);

        summary.LowSeverityCount = result.BypassAttempts.Count(b => b.Severity > 0 && b.Severity < 5) +
                                    result.Detections.Count(d => d.Severity > 0 && d.Severity < 5);

        result = _scoring.CalculateScore(result);
        summary.Verdict = _scoring.GetVerdict(result.TotalScore);
        summary.Explanation = BuildExplanation(result, summary);

        return summary;
    }

    private string BuildExplanation(ScanResult result, Summary summary)
    {
        var parts = new List<string>();

        if (result.TotalScore >= 8)
        {
            parts.Add("YUKSEK GUVENIRLIKLE HILE TESPITI: Bu sistemde birden fazla hile/cheat gostergesi bulunmustur.");
        }
        else if (result.TotalScore >= 5)
        {
            parts.Add("SUPHELI BULGULAR: Sistemde bazi supheli aktiviteler tespit edilmistir. Detayli manuel kontrol onerilir.");
        }
        else if (result.TotalScore >= 3)
        {
            parts.Add("HAFIF SUPHELI: Dusuk seviyede bazi anormallikler bulunmustur, ancak kesin hile kaniti yoktur.");
        }
        else
        {
            parts.Add("TEMIZ: Sistemde herhangi bir hile veya bypass gostergesine rastlanmamistir.");
        }

        if (summary.FoundCategories.Count > 0)
        {
            parts.Add($"\nTespit Edilen Kategoriler: {string.Join(", ", summary.FoundCategories)}");
        }

        if (result.BrowserHistory.Count > 0)
        {
            var cheatSearches = result.BrowserHistory
                .GroupBy(h => h.MatchReason)
                .Select(g => $"{g.Key} ({g.Count()} kez)")
                .ToList();
            parts.Add($"\nBrowser Gecmisi Taramasi: {result.BrowserHistory.Count} supheli kayit bulundu.");
            parts.Add($"Aranan terimler: {string.Join(", ", cheatSearches.Take(5))}");
        }

        var suspiciousFileCount = result.SuspiciousFiles.Count(f => f.IsSuspicious);
        if (suspiciousFileCount > 0)
        {
            var fileNames = result.SuspiciousFiles
                .Where(f => f.IsSuspicious)
                .Select(f => f.Name)
                .Distinct()
                .ToList();
            parts.Add($"\nSupheli Dosyalar: {fileNames.Count} supheli dosya tespit edildi.");
            foreach (var file in fileNames.Take(10))
            {
                var explanation = summary.FileExplanations.GetValueOrDefault(file, "Supheli dosya");
                parts.Add($"- {file}: {explanation}");
            }
            if (fileNames.Count > 10)
                parts.Add($"... ve {fileNames.Count - 10} dosya daha.");
        }

        if (result.DeletedFiles.Count > 0)
        {
            var susDel = result.DeletedFiles.Count(f => f.IsSuspicious);
            parts.Add($"\nSilinen Dosyalar: {result.DeletedFiles.Count} silinen dosya kaydi (USN/Recycle Bin), {susDel} tanesi supheli.");
            foreach (var df in result.DeletedFiles.Where(f => f.IsSuspicious).Take(8))
                parts.Add($"- {df.Name}: {df.Reason}");
        }

        var suspiciousProcCount = result.SuspiciousProcesses.Count(p => p.IsSuspicious);
        if (suspiciousProcCount > 0)
        {
            var procNames = result.SuspiciousProcesses
                .Where(p => p.IsSuspicious)
                .Select(p => p.ProcessName)
                .Distinct()
                .ToList();
            parts.Add($"\nCalisan Supheli Process'ler: {procNames.Count} tane");
            parts.Add(string.Join(", ", procNames.Take(5)));
        }

        if (result.BypassAttempts.Count > 0)
        {
            parts.Add($"\nBypass Girisimleri: {result.BypassAttempts.Count} tane tespit edildi:");
            foreach (var bypass in result.BypassAttempts.OrderByDescending(b => b.Severity).Take(5))
            {
                parts.Add($"- [{bypass.Severity}/10] {bypass.Type}: {bypass.Detail}");
            }
        }

        if (result.NetworkConnections.Count(n => n.IsSuspicious) > 0)
        {
            var netCount = result.NetworkConnections.Count(n => n.IsSuspicious);
            parts.Add($"\nNetwork Uyarilari: {netCount} tane");
            foreach (var net in result.NetworkConnections.Where(n => n.IsSuspicious).Take(5))
            {
                parts.Add($"- {net.Type}: {net.Detail}");
            }
        }

        return string.Join("\n", parts);
    }

    private string? CategorizeCheat(string fileName, string reason)
    {
        var lower = fileName.ToLower();
        var reasonLower = (reason ?? "").ToLower();

        if (lower.Contains("cheatengine") || lower.Contains("artmoney") || lower.Contains("tsearch") ||
            reasonLower.Contains("memory editor") || reasonLower.Contains("memory scanner"))
            return "Memory Editor";

        if (lower.Contains("injector") || lower.Contains("dumper") || lower.Contains("mapper") ||
            lower.Contains("runpe"))
            return "Injection Tool";

        if (lower.Contains("spoofer") || reasonLower.Contains("spoofer"))
            return "Spoofer/HWID Bypass";

        if (lower.Contains("vpn") || lower.Contains("openvpn") || lower.Contains("wireguard") ||
            lower.Contains("tor"))
            return "VPN/Proxy/Anonymizer";

        if (lower.Contains("debug") || lower.Contains("dbg") || lower.Contains("olly") || lower.Contains("ida") ||
            lower.Contains("dnspy") || lower.Contains("ilspy"))
            return "Debugger/Reverse Engineering";

        if (lower.Contains("executor") || lower.Contains("inject") || lower.Contains("loader"))
            return "Cheat Loader/Executor";

        if (lower.Contains("sandboxie") || lower.Contains("vmware") || lower.Contains("virtualbox") ||
            lower.Contains("qemu"))
            return "Virtualization/Sandbox";

        if (lower.Contains("trainer") || lower.Contains("wemod") || lower.Contains("fling"))
            return "Trainer/Mod Tool";

        if (lower.Contains("processhacker") || lower.Contains("procexp"))
            return "Process Analysis Tool";

        if (lower.Contains("wireshark") || lower.Contains("fiddler") || lower.Contains("charles") ||
            lower.Contains("tcpview"))
            return "Network Analysis Tool";

        if (lower.Contains("python") || lower.Contains("autohotkey") || lower.Contains("autoit"))
            return "Scripting/Macro Tool";

        if (lower.Contains("vmp") || lower.Contains("themida") || lower.Contains("winlicense"))
            return "Obfuscation/Protection Tool";

        if (lower.Contains("gasmask") || lower.Contains("nexus") || lower.Contains("exterium") ||
            lower.Contains("capyprivate") || lower.Contains("0x") || lower.Contains("shine"))
            return "MTA Cheat";

        if (lower.Contains("cleaner") || lower.Contains("eraser") || lower.Contains("timestomp"))
            return "Anti-Forensic Tool";

        if (lower.Contains("pcileech") || lower.Contains("dma"))
            return "DMA Hardware Cheat";

        if (lower.Contains("vape") || lower.Contains("liquidbounce") || lower.Contains("meteor") ||
            lower.Contains("sigma") || lower.Contains("wurst") || lower.Contains("novoline") ||
            lower.Contains("rise client"))
            return "Minecraft Cheat Client";

        return "General Suspicious Tool";
    }

    private string? CategorizeSearch(BrowserHistoryEntry entry)
    {
        var url = (entry.Url + " " + entry.Title).ToLower();
        if (url.Contains("mta") || url.Contains("mtasa") || url.Contains("multitheftauto"))
            return "MTA Cheat Search";
        if (url.Contains("fivem"))
            return "FiveM Cheat Search";
        if (url.Contains("spoofer") || url.Contains("serial"))
            return "Spoofer/Security Bypass";
        if (url.Contains("executor") || url.Contains("injector") || url.Contains("loader"))
            return "Cheat Loader Search";
        if (url.Contains("bypass") || url.Contains("cleaner") || url.Contains("delete") || url.Contains("eraser"))
            return "Bypass/Anti-Forensic Search";
        if (url.Contains("unknowncheats") || url.Contains("ugbase") || url.Contains("mpgh"))
            return "Cheat Forum";
        if (url.Contains("keyauth") || url.Contains("eauth"))
            return "Cheat Authentication";
        if (url.Contains("napse") || url.Contains("ocean") || url.Contains("detect"))
            return "Anti-Cheat Research";
        if (url.Contains("dma") || url.Contains("kernel") || url.Contains("driver"))
            return "Advanced Cheat Technique";
        return null;
    }
}
