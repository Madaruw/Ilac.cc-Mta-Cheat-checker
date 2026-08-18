using System.Text;
using Newtonsoft.Json;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Services;

public class WebhookService
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(20) };

    private const int MaxFieldValue = 900;
    private const int MaxEmbedChars = 5500;
    private const int MaxFieldsPerEmbed = 24;
    private const int LineBudget = 950;

    private const string BotUsername = "ilac.cc cheat mta cheat checker";
    private const string BotAvatar = "https://i.pinimg.com/control1/736x/89/f4/71/89f4710289f82acc7f48fb1bb1d386f7.jpg";
    private const string FinalGif = "https://i.pinimg.com/736x/97/74/c8/9774c830065d7e4828370c5fe73b3b1e.jpg";

    public async Task<bool> SendScanStarted(string webhookUrl, string machineName, string userName)
    {
        if (string.IsNullOrEmpty(webhookUrl)) return false;
        try
        {
            var payload = new
            {
                username = BotUsername,
                avatar_url = BotAvatar,
                embeds = new[]
                {
                    new Dictionary<string, object>
                    {
                        ["title"] = "Tarama Basladi",
                        ["color"] = 0x3498DB,
                        ["description"] = $"```\nKullanici: {Safe(userName, 80)}\nMakine:   {Safe(machineName, 80)}\nTahmini:  ~30-60 saniye\n```\n:hourglass_flowing_sand: Adli tarama yapiliyor...",
            ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc v2.2 | Author: madaruw" },
                        ["timestamp"] = DateTime.UtcNow.ToString("o")
                    }
                }
            };
            return await PostPayload(webhookUrl, payload);
        }
        catch { return false; }
    }

    public async Task<bool> SendQuotaExceeded(string webhookUrl)
    {
        if (string.IsNullOrEmpty(webhookUrl)) return false;
        try
        {
            var payload = new
            {
                username = BotUsername,
                avatar_url = BotAvatar,
                embeds = new[]
                {
                    new Dictionary<string, object>
                    {
                        ["title"] = "AI Quota Bitti",
                        ["color"] = 0xE74C3C,
                        ["description"] = "Groq AI analizi yapilamadi. Gunluk istek limitine ulasilmis olabilir.\n\n" +
                            "**Yeni Groq API Key Alma Adimlari:**\n" +
                            "1. https://console.groq.com adresine gidin\n" +
                            "2. Hesap olusturun / giris yapin\n" +
                            "3. Sol menuden 'API Keys' secin\n" +
                            "4. 'Create API Key' ile key olusturun\n" +
                            "5. ilac.cc Builder'i acin\n" +
                            "6. Advanced sekmesine girin\n" +
                            "7. 'Groq API Key' kutusuna key'i yapistirin\n" +
                            "8. 'Kaydet' butonuna tiklayin\n" +
                            "9. Client'i yeniden build edin\n\n" +
                            "**Ucretsiz limit:** Dakikada 30 istek, gunde 14.400 istek",
                        ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc | Author: madaruw" }
                    }
                }
            };
            return await PostPayload(webhookUrl, payload);
        }
        catch { return false; }
    }

    public async Task<bool> SendFinalGif(string webhookUrl)
    {
        if (string.IsNullOrEmpty(webhookUrl)) return false;
        try
        {
            var payload = new
            {
                username = BotUsername,
                avatar_url = BotAvatar,
                embeds = new[]
                {
                    new Dictionary<string, object>
                    {
                        ["title"] = "Tarama Tamamlandi",
                        ["color"] = 0x28A745,
                        ["image"] = new Dictionary<string, object> { ["url"] = FinalGif },
                        ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc | Author: madaruw" }
                    }
                }
            };
            var json = JsonConvert.SerializeObject(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    var response = await _http.PostAsync(webhookUrl, content);
                    if (response.IsSuccessStatusCode) return true;
                    await Task.Delay(700);
                }
                catch { await Task.Delay(700); }
            }
            return false;
        }
        catch { return false; }
    }

    public async Task<bool> SendAiAnalysis(string webhookUrl, string analysis, string title = "AI Cevap")
    {
        if (string.IsNullOrEmpty(webhookUrl) || string.IsNullOrEmpty(analysis)) return false;
        try
        {
            var chunks = ChunkText(analysis, 3500);
            var ok = false;
            foreach (var chunk in chunks)
            {
                var payload = new
                {
                    username = BotUsername,
                avatar_url = BotAvatar,
                    embeds = new[]
                    {
                        new Dictionary<string, object>
                        {
                            ["title"] = title,
                            ["color"] = 0x9B59B6,
                            ["description"] = chunk,
                            ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc | Author: madaruw" }
                        }
                    }
                };
                if (await PostPayload(webhookUrl, payload)) ok = true;
                await Task.Delay(700);
            }
            return ok;
        }
        catch { return false; }
    }

    public async Task<bool> SendAiButton(string webhookUrl, int questionsLeft)
    {
        if (string.IsNullOrEmpty(webhookUrl)) return false;
        try
        {
            var payload = new
            {
                username = BotUsername,
                avatar_url = BotAvatar,
                embeds = new[]
                {
                    new Dictionary<string, object>
                    {
                        ["title"] = questionsLeft > 0 ? $"Soru Sor ({questionsLeft} hak)" : "Soru Hakkiniz Doldu",
                        ["color"] = questionsLeft > 0 ? 0x28A745 : 0xE74C3C,
                        ["description"] = questionsLeft > 0
                            ? "Sorunuzu client console'da yazin. Cevap buraya gonderilecektir."
                            : "5 soru hakkiniz bitmistir.",
                        ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc | Author: madaruw" }
                    }
                }
            };
            return await PostPayload(webhookUrl, payload);
        }
        catch { return false; }
    }

    public async Task<bool> SendResult(string webhookUrl, ScanResult result)
    {
        if (string.IsNullOrEmpty(webhookUrl)) return false;
        try
        {
            var allEmbeds = BuildAllEmbeds(result);

            // Log embed count
            try
            {
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "ilac_scan_debug.log"),
                    $"[{DateTime.Now:HH:mm:ss}] Embeds built: {allEmbeds.Count} | MTA: {result.MtaSpecificCheats.Count} | SuspiciousFiles: {result.SuspiciousFiles.Count(f => f.IsSuspicious)} | DeletedFiles: {result.DeletedFiles.Count}\n");
            }
            catch { }

            if (allEmbeds.Count == 0) return false;

            var ok = false;
            for (int i = 0; i < allEmbeds.Count; i++)
            {
                var payload = new { username = BotUsername, avatar_url = BotAvatar, embeds = new[] { allEmbeds[i] } };
                var sent = await PostPayload(webhookUrl, payload);
                if (sent) ok = true;

                // Log each embed status
                try
                {
                    File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_scan_debug.log"),
                        $"  Embed {i+1}/{allEmbeds.Count}: {(sent ? "OK" : "FAILED")}\n");
                }
                catch { }

                await Task.Delay(700);
            }
            return ok;
        }
        catch (Exception ex)
        {
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ilac_scan_debug.log"), $"EXCEPTION: {ex}"); } catch { }
            return false;
        }
    }

    private async Task<bool> PostPayload(string webhookUrl, object payload)
    {
        try
        {
            var json = JsonConvert.SerializeObject(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    var response = await _http.PostAsync(webhookUrl, content);
                    if (response.IsSuccessStatusCode) return true;
                    var errBody = await response.Content.ReadAsStringAsync();
                    // Log the error for debugging
                    try
                    {
                        File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_webhook_error.log"),
                            $"[{DateTime.Now:HH:mm:ss}] Status: {response.StatusCode} | JSON len: {json.Length} | Body: {errBody.Substring(0, Math.Min(300, errBody.Length))}\n");
                    }
                    catch { }
                    if ((int)response.StatusCode == 429) await Task.Delay(1500 * (attempt + 1));
                    else await Task.Delay(500);
                }
                catch { }
            }
        }
        catch { }
        return false;
    }

    private List<Dictionary<string, object>> BuildAllEmbeds(ScanResult result)
    {
        var embeds = new List<Dictionary<string, object>>();
        var summary = result.Summary;
        var hasMta = result.MtaSpecificCheats.Count > 0;

        // ── 1. MAIN REPORT ──
        var mainColor = result.TotalScore >= 7 ? 0xE74C3C :
                        result.TotalScore >= 4 ? 0xF39C12 : 0x2ECC71;
        var verdictEmoji = result.TotalScore >= 7 ? ":rotating_light:" :
                           result.TotalScore >= 4 ? ":warning:" : ":white_check_mark:";

        embeds.Add(new Dictionary<string, object>
        {
            ["title"] = $"{verdictEmoji} ilac.cc Scan Report",
            ["color"] = mainColor,
            ["fields"] = new List<Dictionary<string, object>>
            {
                new()
                {
                    ["name"] = "Sistem Bilgisi",
                    ["value"] = $"```\nKullanici: {Safe(result.UserName, 120)}\nMakine:   {Safe(result.MachineName, 120)}\nWindows:  {Safe(result.WindowsVersion, 250)}\nZaman:    {result.ScanTime:yyyy-MM-dd HH:mm:ss} UTC\n```",
                    ["inline"] = false
                },
                new()
                {
                    ["name"] = "Verdict",
                    ["value"] = $"```\nSkor:    {result.TotalScore}/{result.MaxScore}\nVerdict: {Safe(summary.Verdict, 250)}\nTespit:  {summary.TotalDetections}\n─────────────────────\nHigh:    {summary.HighSeverityCount}\nMed:     {summary.MediumSeverityCount}\nLow:     {summary.LowSeverityCount}\nMTA:     {(hasMta ? $"EVET ({result.MtaSpecificCheats.Count})" : "HAYIR")}\n```",
                    ["inline"] = false
                }
            },
            ["footer"] = new Dictionary<string, object> { ["text"] = $"ilac.cc v2.2 | Author: madaruw | ID: {Guid.NewGuid():N}" },
            ["timestamp"] = DateTime.UtcNow.ToString("o")
        });

        // ── 2. MTA-SPECIFIC CHEATS ──
        if (hasMta)
        {
            var mtaFiles = result.MtaSpecificCheats
                .GroupBy(f => f.Name.ToLower())
                .Select(g => g.First())
                .ToList();

            var lines = mtaFiles.Select(f =>
            {
                var when = f.LastModifiedTime.HasValue ? $" [{f.LastModifiedTime.Value:MM-dd HH:mm}]" : "";
                return $"{Safe(f.Name, 45)} ({Safe(f.Source, 18)}){when} — {Safe(f.Reason, 100)}";
            }).ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":rotating_light: MTA HILE TESPITI ({mtaFiles.Count})",
                0xE74C3C, lines, "MTA Cheats"));
        }

        // ── 3. GENERAL SUSPICIOUS FILES ──
        var generalFiles = result.SuspiciousFiles
            .Where(f => f.IsSuspicious && !result.MtaSpecificCheats.Contains(f))
            .GroupBy(f => f.Name.ToLower())
            .Select(g => g.First())
            .ToList();

        if (generalFiles.Count > 0)
        {
            var lines = generalFiles.Select(f =>
            {
                var when = f.LastModifiedTime.HasValue ? $" [{f.LastModifiedTime.Value:MM-dd HH:mm}]" : "";
                return $"{Safe(f.Name, 45)} ({Safe(f.Source, 18)}){when} — {Safe(f.Reason, 100)}";
            }).ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":orange_circle: Genel Supheli Dosyalar ({generalFiles.Count})",
                0xF39C12, lines, "Files"));
        }

        // ── 4a. MTA-RELATED DELETED FILES ──
        if (result.DeletedFiles.Count > 0)
        {
            var mtaDeleted = result.DeletedFiles
                .Where(f => KnownCheats.IsMtaCheat(f.Name, null, f.Reason) ||
                            KnownCheats.ContainsCheatBrand(f.Name))
                .ToList();
            if (mtaDeleted.Count > 0)
            {
                var lines = mtaDeleted.Select(f =>
                {
                    var when = f.LastModifiedTime.HasValue ? f.LastModifiedTime.Value.ToString("MM-dd HH:mm") : "?";
                    return $"{Safe(f.Name, 45)} — {Safe(f.Reason, 80)} [{when}]";
                }).ToList();
                embeds.AddRange(BuildSectionEmbeds(
                    $"MTA Hile Dosyasi Silinmis ({mtaDeleted.Count})",
                    0xFF0000, lines, "MTA Deleted"));
            }

            // ── 4b. ALL DELETED FILES ──
            var delFiles = result.DeletedFiles
                .OrderByDescending(f => f.LastModifiedTime ?? DateTime.MinValue)
                .Take(200)
                .ToList();

            var delLines = delFiles.Select(f =>
            {
                var when = f.LastModifiedTime.HasValue ? f.LastModifiedTime.Value.ToString("MM-dd HH:mm") : "?";
                var flag = f.IsSuspicious ? " [!]" : "";
                return $"[{when}] {Safe(f.Name, 50)}{flag}";
            }).ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $"Silinen Dosyalar ({result.DeletedFiles.Count})",
                0x8B0000, delLines, "Deleted"));
        }

        // ── 5. RECENTLY EXECUTED PROGRAMS ──
        if (result.RecentlyExecuted.Count > 0)
        {
            var lines = result.RecentlyExecuted
                .Take(50)
                .Select(n => $"• {Safe(n, 80)}.exe")
                .ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":stopwatch: Son Calistirilan Programlar ({result.RecentlyExecuted.Count})",
                0x2ECC71, lines, "Recent"));
        }

        // ── 6. SUSPICIOUS PROCESSES ──
        var susProcs = result.SuspiciousProcesses.Where(p => p.IsSuspicious).ToList();
        if (susProcs.Count > 0)
        {
            var lines = susProcs.Select(p =>
                $"{Safe(p.ProcessName, 40)} (PID:{p.PID}) — {Safe(p.Reason, 80)}").ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":desktop: Supheli Surecler ({susProcs.Count})",
                0xE74C3C, lines, "Processes"));
        }

        // ── 7. BYPASS ATTEMPTS ──
        if (result.BypassAttempts.Count > 0)
        {
            var lines = result.BypassAttempts
                .OrderByDescending(b => b.Severity)
                .Select(b => $"[{b.Severity}/10] {Safe(b.Type, 40)} — {Safe(b.Detail, 120)}").ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":no_entry: Bypass Girisimleri ({result.BypassAttempts.Count})",
                0xE74C3C, lines, "Bypass"));
        }

        // ── 8. DRIVER / BOOT SECURITY ──
        var driverDets = result.Detections
            .Where(d => d.Category == "Driver" || d.Category == "Boot Config" ||
                        d.Category == "Recently Loaded Driver")
            .ToList();
        if (driverDets.Count > 0)
        {
            var lines = driverDets
                .OrderByDescending(d => d.Severity)
                .Select(d => $"{Safe(d.Name, 50)} — {Safe(d.Detail, 100)}").ToList();

            embeds.AddRange(BuildSectionEmbeds(
                $":truck: Driver & Boot Guvenligi ({driverDets.Count})",
                0xC0392B, lines, "Drivers"));
        }

        // ── 9. OTHER DETECTIONS ──
        var otherDets = result.Detections
            .Where(d => d.Category != "Driver" && d.Category != "Boot Config" &&
                        d.Category != "Recently Loaded Driver" && d.Severity > 0)
            .OrderByDescending(d => d.Severity)
            .ToList();
        if (otherDets.Count > 0)
        {
            var lines = otherDets
                .Select(d => $"{Safe(d.Name, 50)} — {Safe(d.Detail, 100)}").ToList();
            embeds.AddRange(BuildSectionEmbeds(
                $":mag: Ek Tespitler ({otherDets.Count})",
                0xF39C12, lines, "Detections"));
        }

        // ── 10. BROWSER HISTORY ──
        var susHistory = result.BrowserHistory.Where(h => h.IsSuspicious).ToList();
        if (susHistory.Count > 0)
        {
            var lines = susHistory
                .Select(h => $"{Safe(h.MatchReason, 60)} — {Safe(h.Title, 60)}").ToList();
            embeds.AddRange(BuildSectionEmbeds(
                $":globe_with_meridians: Browser Gecmisi ({susHistory.Count})",
                0xF39C12, lines, "History"));
        }

        // ── 12. FINAL SUMMARY ──
        embeds.Add(BuildFinalSummary(result, hasMta));

        // ── 13. SORU SOR BUTONU ──
        embeds.Add(new Dictionary<string, object>
        {
            ["title"] = "Soru Sor (5 hak)",
            ["color"] = 0x28A745,
            ["description"] = "Tarama sonuclari hakkinda soru sormak icin client console'da yazin.\n5 soru hakkiniz vardir. Sorulariniz ve cevaplar buraya gonderilecektir.",
            ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc | Author: madaruw | AI Soru" }
        });

        return embeds;
    }

    private Dictionary<string, object> BuildFinalSummary(ScanResult result, bool hasMta)
    {
        var sb = new StringBuilder();
        sb.AppendLine("```");
        sb.AppendLine("═══════════════════════════════════════");
        sb.AppendLine("         TARAMA OZETI");
        sb.AppendLine("═══════════════════════════════════════");
        sb.AppendLine();

        if (hasMta)
        {
            sb.AppendLine("  MTA HILE: EVET");
            sb.AppendLine($"  MTA Hile Sayisi: {result.MtaSpecificCheats.Count}");
            sb.AppendLine();
            sb.AppendLine("  Tespit Edilen MTA Hileleri:");

            var distinct = result.MtaSpecificCheats
                .GroupBy(f => f.Name.ToLower())
                .Select(g => g.First())
                .ToList();

            foreach (var f in distinct)
            {
                sb.AppendLine($"    • {Safe(f.Name, 45)}");
                sb.AppendLine($"      {Safe(f.Reason, 60)}");
            }
        }
        else
        {
            sb.AppendLine("  MTA HILE: HAYIR");
            sb.AppendLine("  MTA'ya ozgu hile bulunamadi.");
        }

        sb.AppendLine();
        sb.AppendLine("───────────────────────────────────────");
        sb.AppendLine($"  Genel Skor:     {result.TotalScore}/{result.MaxScore}");
        sb.AppendLine($"  Verdict:        {Safe(result.Summary?.Verdict ?? "", 40)}");
        sb.AppendLine($"  Toplam Tespit:  {result.Summary?.TotalDetections ?? 0}");
        sb.AppendLine($"  Silinen Dosya:  {result.DeletedFiles.Count}");
        sb.AppendLine($"  Son Calistirilan: {result.RecentlyExecuted.Count}");

        if (result.BypassAttempts.Count > 0)
        {
            sb.AppendLine("───────────────────────────────────────");
            sb.AppendLine($"  BYPASS TESPITI: {result.BypassAttempts.Count}");
            foreach (var b in result.BypassAttempts.OrderByDescending(b => b.Severity).Take(5))
                sb.AppendLine($"    [{b.Severity}/10] {Safe(b.Type, 35)}");
        }

        if (result.DeletedFiles.Count(f => f.IsSuspicious) > 0)
        {
            sb.AppendLine("───────────────────────────────────────");
            sb.AppendLine($"  SUPHELI SILINEN: {result.DeletedFiles.Count(f => f.IsSuspicious)}");
            foreach (var f in result.DeletedFiles.Where(f => f.IsSuspicious).Take(5))
                sb.AppendLine($"    • {Safe(f.Name, 45)}");
        }

        sb.AppendLine("═══════════════════════════════════════");
        sb.AppendLine("```");

        return new Dictionary<string, object>
        {
            ["title"] = hasMta ? ":rotating_light: MTA Hile Ozeti" : ":clipboard: Tarama Ozeti",
            ["color"] = hasMta ? 0xE74C3C : 0x2ECC71,
            ["description"] = sb.ToString(),
            ["footer"] = new Dictionary<string, object> { ["text"] = "ilac.cc v2.2 Forensic Scanner" },
            ["timestamp"] = DateTime.UtcNow.ToString("o")
        };
    }

    private List<Dictionary<string, object>> BuildSectionEmbeds(string title, int color,
        List<string> lines, string fieldNameBase)
    {
        var embeds = new List<Dictionary<string, object>>();
        var fields = new List<Dictionary<string, object>>();
        var currentField = new StringBuilder();
        int fieldIdx = 0;
        int part = 0;

        void FlushField()
        {
            if (currentField.Length == 0) return;
            fields.Add(new Dictionary<string, object>
            {
                ["name"] = fieldIdx == 0 ? fieldNameBase : $"{fieldNameBase} (devam {fieldIdx + 1})",
                ["value"] = currentField.ToString().TrimEnd('\n'),
                ["inline"] = false
            });
            currentField.Clear();
            fieldIdx++;
        }

        void FlushEmbed()
        {
            FlushField();
            if (fields.Count == 0) return;
            embeds.Add(new Dictionary<string, object>
            {
                ["title"] = part == 0 ? title : $"{title} (devam {part + 1})",
                ["color"] = color,
                ["fields"] = fields
            });
            fields = new List<Dictionary<string, object>>();
            fieldIdx = 0;
            part++;
        }

        // Code blocks add overhead of 8 chars (```\n...\n```)
        int embedCharTotal = 0;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Length > LineBudget ? rawLine.Substring(0, LineBudget) + "…" : rawLine;
            if (line.Length > MaxFieldValue - 4) line = line.Substring(0, MaxFieldValue - 4) + "…";
            line = "• " + line;

            bool needNewField = currentField.Length > 0 && currentField.Length + line.Length + 3 > MaxFieldValue;
            bool needNewEmbed = fields.Count >= MaxFieldsPerEmbed || embedCharTotal + line.Length + 60 > 4800;

            if (needNewEmbed) { FlushEmbed(); embedCharTotal = 0; }
            else if (needNewField) FlushField();

            if (currentField.Length > 0) currentField.Append("\n");
            currentField.Append(line);
            currentField.Append("\n");
            embedCharTotal += line.Length + 2;
        }

        FlushEmbed();
        return embeds;
    }

    private static List<string> ChunkText(string text, int maxSize)
    {
        var chunks = new List<string>();
        if (string.IsNullOrEmpty(text)) return chunks;
        for (int i = 0; i < text.Length; i += maxSize)
            chunks.Add(text.Substring(i, Math.Min(maxSize, text.Length - i)));
        return chunks;
    }

    private static string Safe(string s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.Length <= max) return s;
        return s.Substring(0, max) + "…";
    }
}
