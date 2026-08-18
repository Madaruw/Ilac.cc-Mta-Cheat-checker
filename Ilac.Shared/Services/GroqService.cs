using System.Text;
using Newtonsoft.Json;
using Ilac.Shared.Models;

namespace Ilac.Shared.Services;

public class GroqService
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    public bool QuotaExceeded { get; private set; }
    public bool ConnectionFailed { get; private set; }
    public bool Connected => !QuotaExceeded && !ConnectionFailed;
    public string LastError { get; private set; } = "";

    private static readonly string[] Models =
    {
        "groq/compound",
        "groq/compound-mini",
    };

    public async Task<string> AskQuestion(string apiKey, string question)
    {
        if (string.IsNullOrEmpty(apiKey)) return "API key yok.";
        if (string.IsNullOrEmpty(question)) return "";

        var prompt = $"Bir kullanici MTA (Multi Theft Auto) hile tarama araci kullaniyor ve su soruyu sordu:\n\n\"{question}\"\n\nBu soruyu Turkce ve aciklayici sekilde yanitla. MTA hile tespiti ile ilgiliyse teknik detay ver.";

        var text = await SendChat(apiKey, prompt, 3000, 0.5);
        if (text == null)
        {
            if (QuotaExceeded) return "AI su an kullanilamiyor (Groq gunluk istek limiti dolmus olabilir).";
            return string.IsNullOrEmpty(LastError) ? "AI su an kullanilamiyor." : $"AI istegi basarisiz: {LastError}";
        }
        return text;
    }

    public async Task<string> AnalyzeScanResult(string apiKey, ScanResult result)
    {
        if (string.IsNullOrEmpty(apiKey)) return "";
        if (result == null) return "";

        var prompt = BuildPrompt(result);
        var text = await SendChat(apiKey, prompt, 1500, 0.4);
        return text ?? "";
    }

    private async Task<string?> SendChat(string apiKey, string prompt, int maxTokens, double temperature)
    {
        QuotaExceeded = false;
        ConnectionFailed = false;
        LastError = "";
        int totalAttempts = 0;
        int quotaAttempts = 0;

        try
        {
            foreach (var model in Models)
            {
                for (int retry = 0; retry < 1; retry++)
                {
                    totalAttempts++;
                    try
                    {
                        var url = "https://api.groq.com/openai/v1/chat/completions";
                        var requestBody = new
                        {
                            model = model,
                            messages = new[]
                            {
                                new { role = "user", content = prompt }
                            },
                            temperature = temperature,
                            max_tokens = maxTokens
                        };
                        var json = JsonConvert.SerializeObject(requestBody);
                        var request = new HttpRequestMessage(HttpMethod.Post, url)
                        {
                            Content = new StringContent(json, Encoding.UTF8, "application/json")
                        };
                        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {apiKey}");

                        var response = await _http.SendAsync(request);

                        if (response.IsSuccessStatusCode)
                        {
                            var responseJson = await response.Content.ReadAsStringAsync();
                            var data = JsonConvert.DeserializeObject<dynamic>(responseJson);
                            var text = data?.choices?[0]?.message?.content?.ToString();
                            return text ?? "";
                        }

                        var statusCode = (int)response.StatusCode;
                        var errBody = await response.Content.ReadAsStringAsync();
                        try
                        {
                            var logPath = Path.Combine(Path.GetTempPath(), "ilac_groq_error.log");
                            File.AppendAllText(logPath,
                                $"[{DateTime.Now:HH:mm:ss}] Model: {model} | Status: {response.StatusCode} | Body: {errBody.Substring(0, Math.Min(300, errBody.Length))}\n");
                        }
                        catch { }

                        if (statusCode == 429) { quotaAttempts++; await Task.Delay(3000 * (retry + 1)); continue; }
                        LastError = $"HTTP {statusCode} ({model}): {TrimError(errBody)}{StatusHint(statusCode, errBody)}";
                        break;
                    }
                    catch (Exception ex)
                    {
                        ConnectionFailed = true;
                        LastError = $"Baglanti hatasi: {ex.Message}";
                        await Task.Delay(2000);
                    }
                }
            }

            if (totalAttempts > 0 && quotaAttempts == totalAttempts)
                QuotaExceeded = true;
            else if (totalAttempts > 0)
                ConnectionFailed = true;

            return null;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            return null;
        }
    }

    private string BuildPrompt(ScanResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Sen bir MTA hile tespit analizistisin. Asagidaki tarama sonuclarini KISA ve OZ sekilde analiz et.");
        sb.AppendLine("Sadece MTA hilelerini ve gercekten supheli dosyalari degerlendir.");
        sb.AppendLine("Anti-forensic analiz, risk degerlendirmesi, oneriler gibi uzun bolumler YAPMA.");
        sb.AppendLine("Kisa ve oz, tam olarak su 3 seyi soyle:");
        sb.AppendLine("1) HILE DURUMU: Kisinin hile kullanip kullanmadigi. (HILE VAR / SUPPHELI / HILE YOK)");
        sb.AppendLine("2) TESPIT EDILEN HILE: Hangi hile/arac tespit edildi, ne ise yarar ve NASIL CALISTIGI (kisa, teknik olmayan 2-3 cumle)");
        sb.AppendLine("3) OZET KARAR: 2-3 cumle ile sonuc");
        sb.AppendLine("Turkce yanit ver. Maksimum 150 kelime. Baslik veya uzun giris YAPMA, dogrudan maddelere gec.\n");

        sb.AppendLine($"═══════════════════════════════════════");
        sb.AppendLine($"TARAMA SONUCLARI");
        sb.AppendLine($"═══════════════════════════════════════\n");

        sb.AppendLine($"Makine: {result.MachineName}");
        sb.AppendLine($"Kullanici: {result.UserName}");
        sb.AppendLine($"Windows: {result.WindowsVersion}");
        sb.AppendLine($"Skor: {result.TotalScore}/{result.MaxScore}");
        sb.AppendLine($"Verdict: {result.Summary?.Verdict}");
        sb.AppendLine($"Toplam Tespit: {result.Summary?.TotalDetections}");
        sb.AppendLine();

        if (result.MtaSpecificCheats.Count > 0)
        {
            sb.AppendLine($"--- MTA HILELERI ({result.MtaSpecificCheats.Count}) ---");
            var distinct = result.MtaSpecificCheats
                .GroupBy(f => f.Name.ToLower())
                .Select(g => g.First())
                .ToList();
            foreach (var f in distinct)
            {
                sb.AppendLine($"  DOSYA: {f.Name}");
                sb.AppendLine($"  KAYNAK: {f.Source}");
                sb.AppendLine($"  SEBEP: {f.Reason}");
                if (f.LastModifiedTime.HasValue)
                    sb.AppendLine($"  ZAMAN: {f.LastModifiedTime.Value:yyyy-MM-dd HH:mm}");
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("--- MTA HILELERI: BULUNAMADI ---\n");
        }

        var genCount = result.SuspiciousFiles.Count(f => f.IsSuspicious);
        sb.AppendLine($"--- GENEL SUPHELI DOSYALAR ({genCount}) ---");
        var genFiles = result.SuspiciousFiles
            .Where(f => f.IsSuspicious && !result.MtaSpecificCheats.Contains(f))
            .GroupBy(f => f.Name.ToLower())
            .Select(g => g.First())
            .Take(30);
        foreach (var f in genFiles)
        {
            sb.AppendLine($"  {f.Name} ({f.Source}): {f.Reason}");
        }
        sb.AppendLine();

        if (result.DeletedFiles.Count > 0)
        {
            sb.AppendLine($"--- SILINEN DOSYALAR ({result.DeletedFiles.Count}) ---");
            foreach (var f in result.DeletedFiles.Take(15))
            {
                var when = f.LastModifiedTime.HasValue ? f.LastModifiedTime.Value.ToString("yyyy-MM-dd HH:mm") : "?";
                sb.AppendLine($"  [{when}] {f.Name}: {f.Reason}");
            }
            sb.AppendLine();
        }

        if (result.RecentlyExecuted.Count > 0)
        {
            sb.AppendLine($"--- SON CALISTIRILAN PROGRAMLAR ({result.RecentlyExecuted.Count}) ---");
            foreach (var n in result.RecentlyExecuted.Take(20))
                sb.AppendLine($"  {n}.exe");
            sb.AppendLine();
        }

        var susProcs = result.SuspiciousProcesses.Where(p => p.IsSuspicious).ToList();
        if (susProcs.Count > 0)
        {
            sb.AppendLine($"--- SUPHELI SURECLER ({susProcs.Count}) ---");
            foreach (var p in susProcs)
                sb.AppendLine($"  {p.ProcessName} (PID:{p.PID}): {p.Reason}");
            sb.AppendLine();
        }

        if (result.BypassAttempts.Count > 0)
        {
            sb.AppendLine($"--- BYPASS GIRISIMLERI ({result.BypassAttempts.Count}) ---");
            foreach (var b in result.BypassAttempts.OrderByDescending(b => b.Severity))
                sb.AppendLine($"  [{b.Severity}/10] {b.Type}: {b.Detail}");
            sb.AppendLine();
        }

        if (result.LoadedDrivers.Count > 0)
        {
            sb.AppendLine($"--- YUKLU DRIVER SAYISI: {result.LoadedDrivers.Count} ---");
            var susDrivers = result.Detections
                .Where(d => d.Category == "Driver" || d.Category == "Recently Loaded Driver")
                .ToList();
            if (susDrivers.Count > 0)
            {
                sb.AppendLine($"  SUPHELI DRIVERLAR ({susDrivers.Count}):");
                foreach (var d in susDrivers)
                    sb.AppendLine($"    {d.Name}: {d.Detail}");
            }
            sb.AppendLine();
        }

        var susHistory = result.BrowserHistory.Where(h => h.IsSuspicious).ToList();
        if (susHistory.Count > 0)
        {
            sb.AppendLine($"--- BROWSER GECMISI ({susHistory.Count}) ---");
            foreach (var h in susHistory.Take(15))
                sb.AppendLine($"  {h.MatchReason}: {h.Title}");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string TrimError(string body)
    {
        if (string.IsNullOrEmpty(body)) return "bilinmeyen hata";
        var flat = System.Text.RegularExpressions.Regex.Replace(body, @"\s+", " ").Trim();
        return flat.Length > 200 ? flat.Substring(0, 200) + "..." : flat;
    }

    private static string StatusHint(int statusCode, string body)
    {
        var b = body ?? "";
        if (statusCode == 401 || statusCode == 403 || b.Contains("invalid"))
            return " | NOT: API key gecersiz veya reddedildi. Yeni key al: https://console.groq.com";
        if (statusCode == 400)
            return " | NOT: istek formatinda sorun var (400).";
        if (statusCode == 404)
            return " | NOT: model bulunamadi (404).";
        return "";
    }
}