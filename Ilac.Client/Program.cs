using System.Diagnostics;
using Ilac.Shared;
using Ilac.Shared.Models;
using Ilac.Shared.Services;

namespace Ilac.Client;

class Program
{
    static async Task Main(string[] args)
    {
        Console.Title = "ilac.cc MTA Cheat Checker";
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Check admin — if not admin, restart as admin
        if (!IsAdministrator())
        {
            Console.WriteLine("[*] Admin izni gerekiyor...");
            var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "";
            if (!string.IsNullOrEmpty(exePath))
            {
                var psi = new ProcessStartInfo(exePath)
                {
                    Verb = "runas",
                    UseShellExecute = true,
                    Arguments = string.Join(" ", args)
                };
                try { Process.Start(psi); } catch { }
            }
            return;
        }

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("ilac.cc MTA Cheat Checker v1\n");
        Console.ResetColor();

        var config = new ScanConfig();

        // Load Groq key from saved file
        try
        {
            var keyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ilac.cc", "groq_key.txt");
            if (File.Exists(keyPath))
                config.GroqApiKey = File.ReadAllText(keyPath).Trim();
        }
        catch { }

        // Parse webhook from args
        if (args.Length > 0 && (args[0].StartsWith("http://") || args[0].StartsWith("https://")))
            config.WebhookUrl = args[0];

        // Load config from file
        if (string.IsNullOrEmpty(config.WebhookUrl))
        {
            var configFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ilac_config.json");
            if (File.Exists(configFile))
            {
                try
                {
                    var json = File.ReadAllText(configFile);
                    var cfg = Newtonsoft.Json.JsonConvert.DeserializeObject<ScanConfig>(json);
                    if (cfg != null) config = cfg;
                }
                catch { }
            }
        }

        if (string.IsNullOrEmpty(config.WebhookUrl))
        {
            Console.Write("Discord Webhook URL: ");
            config.WebhookUrl = Console.ReadLine()?.Trim() ?? "";
        }

        Console.WriteLine($"\n[*] Hedef: {Environment.MachineName}");
        Console.WriteLine($"[*] Kullanici: {Environment.UserName}");
        Console.WriteLine();

        // Send "scan started" to Discord
        if (!string.IsNullOrEmpty(config.WebhookUrl))
        {
            var webhook = new WebhookService();
            await webhook.SendScanStarted(config.WebhookUrl, Environment.MachineName, Environment.UserName);
        }

        // Run scan with progress bar
        var orchestrator = new ScannerOrchestrator();
        var progress = new Progress<(string stage, int percent)>(p =>
        {
            DrawProgressBar(p.percent, p.stage);
        });

        var result = await orchestrator.RunFullScan(config, progress);

        DrawProgressBar(100, "Tamamlandi");
        Console.WriteLine();
        Console.WriteLine();

        if (!string.IsNullOrEmpty(config.WebhookUrl))
        {
            Console.WriteLine("[+] Sonuclar Discord'a gonderildi.");
            if (result.AiConnected)
                Console.WriteLine("[+] Groq'a baglanildi. AI analizi gonderildi.");
            else if (result.AiQuotaExceeded)
                Console.WriteLine("[!] Groq gunluk istek limiti dolmus olabilir. Discord'a yeni key talimati gonderildi.");
            else
                Console.WriteLine("[!] Groq'a baglanilamadi.");

            // Final: tarama bittikten sonra kisa ve oz AI analizi gonder (hile ne, nasil calisir, hile var mi)
            if (!string.IsNullOrEmpty(result.AiAnalysis))
            {
                Console.Write("[*] AI analizi gonderiliyor...");
                var aiSent = await new WebhookService().SendAiAnalysis(config.WebhookUrl,
                    $"**Hedef:** {Environment.MachineName} ({Environment.UserName})\n\n{result.AiAnalysis}",
                    "AI Analizi (Sonuc)");
                Console.WriteLine(aiSent ? "OK" : "BASARISIZ");
            }

            Console.Write("[*] GIF gonderiliyor...");
            var gifSent = await new WebhookService().SendFinalGif(config.WebhookUrl);
            Console.WriteLine(gifSent ? "OK" : "BASARISIZ");
        }

        var resultJson = Newtonsoft.Json.JsonConvert.SerializeObject(result, Newtonsoft.Json.Formatting.Indented);
        File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ilac_result.json"), resultJson);

        if (!config.SilentMode && !Console.IsInputRedirected)
        {
            Console.WriteLine("\nCikmak icin bir tusa bas...");
            Console.ReadKey();
        }
    }

    static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    static void DrawProgressBar(int percent, string stage)
    {
        var barWidth = 32;
        var filled = (int)((double)percent / 100 * barWidth);
        var bar = new string('█', filled) + new string('░', barWidth - filled);
        var stageText = TruncatePad(stage, 24);
        Console.Write($"\r[*] [{bar}] {percent,3}%  {stageText}");
    }

    static string TruncatePad(string s, int len)
    {
        if (string.IsNullOrEmpty(s)) return new string(' ', len);
        if (s.Length > len) return s.Substring(0, len);
        return s + new string(' ', len - s.Length);
    }
}
