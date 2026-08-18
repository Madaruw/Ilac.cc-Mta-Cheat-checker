using Ilac.Shared.Models;

namespace Ilac.Shared.Services;

public class ScoringService
{
    public ScanResult CalculateScore(ScanResult result)
    {
        int score = 0;
        int maxScore = 10;

        // Browser history - count unique cheat searches (HIGH weight)
        if (result.BrowserHistory.Count > 0)
        {
            var uniqueCheats = result.BrowserHistory
                .Select(h => h.MatchReason)
                .Distinct()
                .Count();
            score += Math.Min(uniqueCheats, 4);
        }

        // Bypass attempts - weighted by severity
        var highBypasses = result.BypassAttempts.Count(b => b.Severity >= 8);
        var medBypasses = result.BypassAttempts.Count(b => b.Severity >= 5 && b.Severity < 8);
        var lowBypasses = result.BypassAttempts.Count(b => b.Severity > 0 && b.Severity < 5);
        score += Math.Min(highBypasses * 2, 4);
        score += Math.Min(medBypasses, 2);
        score += Math.Min(lowBypasses, 1);

        // Suspicious processes - only count actually suspicious ones
        var suspiciousProcs = result.SuspiciousProcesses.Count(p => p.IsSuspicious);
        score += Math.Min(suspiciousProcs * 2, 4);

        // Suspicious files - only count actually suspicious ones (HIGH weight)
        var suspiciousFiles = result.SuspiciousFiles.Count(f => f.IsSuspicious);
        if (suspiciousFiles > 0)
        {
            // Each cheat file is worth 1 point, up to 4
            score += Math.Min(suspiciousFiles, 4);
        }

        // Detections
        var highDetections = result.Detections.Count(d => d.Severity >= 8);
        var medDetections = result.Detections.Count(d => d.Severity >= 5 && d.Severity < 8);
        score += Math.Min(highDetections, 3);
        score += Math.Min(medDetections, 2);

        // Network suspicious connections
        var suspiciousNet = result.NetworkConnections.Count(n => n.IsSuspicious);
        score += Math.Min(suspiciousNet, 2);

        result.TotalScore = Math.Min(score, maxScore);
        result.MaxScore = maxScore;

        return result;
    }

    public string GetVerdict(int score)
    {
        return score switch
        {
            >= 8 => "HILE TESPIT EDILDI (Yuksek Guvenirlik)",
            >= 5 => "SUPHELI (Orta Risk - Manuel Kontrol Gerekli)",
            >= 3 => "Hafif Supheli (Dusuk Risk)",
            _ => "TEMIZ (Cheat Tespit Edilmedi)"
        };
    }
}
