using System.Diagnostics;
using System.Text;
using Ilac.Shared.Models;

namespace Ilac.Shared.Services;

public class ClientBuilderService
{
    public async Task<(bool Success, string? Error)> BuildClient(string outputPath, string webhookUrl, ScanConfig config)
    {
        try
        {
            var clientSource = GenerateClientSource(webhookUrl, config);
            var tempDir = Path.Combine(Path.GetTempPath(), "ilac_build_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            var sourceFile = Path.Combine(tempDir, "Program.cs");
            await File.WriteAllTextAsync(sourceFile, clientSource);

            // Copy app icon to temp dir
            var appIconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
            if (!File.Exists(appIconPath))
            {
                // Try alternative path
                var checkDir = Path.GetDirectoryName(typeof(ClientBuilderService).Assembly.Location);
                if (checkDir != null) appIconPath = Path.Combine(checkDir, "app.ico");
            }
            if (File.Exists(appIconPath))
                File.Copy(appIconPath, Path.Combine(tempDir, "app.ico"), true);

            var sharedProjectPath = FindSharedProjectFile();
            if (sharedProjectPath == null)
                return (false, "Could not find Ilac.Shared.csproj. Make sure the project structure is intact.");

            var csprojContent = GenerateProjectFile(sharedProjectPath);
            var csprojFile = Path.Combine(tempDir, "Ilac.Client.Custom.csproj");
            await File.WriteAllTextAsync(csprojFile, csprojContent);

            // Write app.manifest for admin elevation
            var manifestPath = Path.Combine(tempDir, "app.manifest");
            await File.WriteAllTextAsync(manifestPath,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n" +
                "  <assemblyIdentity version=\"1.0.0.0\" name=\"ilac.client\"/>\n" +
                "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\n" +
                "    <security>\n" +
                "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n" +
                "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>\n" +
                "      </requestedPrivileges>\n" +
                "    </security>\n" +
                "  </trustInfo>\n" +
                "</assembly>\n");

            var sb = new StringBuilder();
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = $"publish \"{csprojFile}\" -c Release -o \"{outputPath}\" --self-contained true -r win-x64 /p:CopyLocalLockFileAssemblies=true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:DebugType=none /p:DebugSymbols=false",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            process.OutputDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
            process.ErrorDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync();

            try { Directory.Delete(tempDir, true); } catch { }

            if (process.ExitCode != 0)
            {
                var errorOutput = sb.ToString();
                return (false, $"dotnet publish failed (exit {process.ExitCode}):\n{errorOutput}");
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static string? FindSharedProjectFile()
    {
        // Single-file publish'de Assembly.Location gecici extraction klasorunu gosterebilir,
        // bu yuzden exe'nin gercek klasorunu veren AppContext.BaseDirectory de denenir.
        var startDirs = new List<string>();
        var assemblyDir = Path.GetDirectoryName(typeof(ClientBuilderService).Assembly.Location);
        if (!string.IsNullOrEmpty(assemblyDir)) startDirs.Add(assemblyDir);
        if (!string.IsNullOrEmpty(AppContext.BaseDirectory)) startDirs.Add(AppContext.BaseDirectory);

        foreach (var start in startDirs)
        {
            var dir = start;
            while (dir != null)
            {
                var candidate = Path.Combine(dir, "Ilac.Shared", "Ilac.Shared.csproj");
                if (File.Exists(candidate)) return candidate;
                var parent = Path.GetDirectoryName(dir);
                if (parent == dir) break;
                dir = parent;
            }
        }
        return null;
    }

    private string GenerateClientSource(string webhookUrl, ScanConfig config)
    {
        var groqKey = config.GroqApiKey ?? "";
        var enableAi = config.EnableAiAnalysis.ToString().ToLower();

        return $$"""
using System;
using System.IO;
using System.Threading.Tasks;
using Ilac.Shared;
using Ilac.Shared.Models;
using Ilac.Shared.Services;

namespace Ilac.Client.Custom;

class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            // Check admin — if not admin, restart as admin
            if (!IsAdministrator())
            {
                Console.WriteLine("[*] Admin izni gerekiyor...");
                var exePath = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (!string.IsNullOrEmpty(exePath))
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(exePath)
                    {
                        Verb = "runas",
                        UseShellExecute = true,
                        Arguments = string.Join(" ", args)
                    };
                    try { System.Diagnostics.Process.Start(psi); } catch { }
                }
                return;
            }

            Console.Title = "ilac.cc MTA Cheat Checker";
            Console.OutputEncoding = System.Text.Encoding.UTF8;
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

            {{(string.IsNullOrEmpty(webhookUrl) ? "" : $"config.WebhookUrl = \"{webhookUrl}\";")}}
            {{(string.IsNullOrEmpty(groqKey) ? "" : $"config.GroqApiKey = \"{groqKey}\";")}}
            config.EnableAiAnalysis = {{enableAi}};

            {{GenerateConfigSettings(config)}}

            if (string.IsNullOrEmpty(config.WebhookUrl))
            {
                var cfgFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ilac_config.json");
                if (File.Exists(cfgFile))
                {
                    try
                    {
                        var cfgJson = File.ReadAllText(cfgFile);
                        var cfg = Newtonsoft.Json.JsonConvert.DeserializeObject<ScanConfig>(cfgJson);
                        if (cfg != null) config = cfg;
                    }
                    catch { }
                }
            }

            if (string.IsNullOrEmpty(config.WebhookUrl) && args.Length > 0)
                config.WebhookUrl = args[0];

            Console.WriteLine($"[*] Hedef: {Environment.MachineName}");
            Console.WriteLine($"[*] Kullanici: {Environment.UserName}");
            Console.WriteLine();

            // Send "scan started" to Discord
            if (!string.IsNullOrEmpty(config.WebhookUrl))
            {
                var webhook = new WebhookService();
                await webhook.SendScanStarted(config.WebhookUrl, Environment.MachineName, Environment.UserName);
            }

            var orchestrator = new ScannerOrchestrator();
            var progress = new Progress<(string stage, int percent)>(p => DrawBar(p.percent, p.stage));
            var result = await orchestrator.RunFullScan(config, progress);

            DrawBar(100, "Tamamlandi");
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
        catch (Exception ex)
        {
            Console.WriteLine($"[ilac.cc] Error: {ex.Message}");
            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ilac_error.log"), ex.ToString());
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

    static void DrawBar(int percent, string stage)
    {
        var barWidth = 32;
        var filled = (int)((double)percent / 100 * barWidth);
        var bar = new string('█', filled) + new string('░', barWidth - filled);
        var s = stage ?? "";
        if (s.Length > 24) s = s.Substring(0, 24);
        s = s + new string(' ', 24 - s.Length);
        Console.Write($"\r[*] [{bar}] {percent,3}%  {s}");
    }
}
""";
    }

    private string GenerateConfigSettings(ScanConfig config)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"config.ScanBrowserHistory = {config.ScanBrowserHistory.ToString().ToLower()};");
        sb.AppendLine($"config.ScanPrefetch = {config.ScanPrefetch.ToString().ToLower()};");
        sb.AppendLine($"config.ScanBAM = {config.ScanBAM.ToString().ToLower()};");
        sb.AppendLine($"config.ScanAmCache = {config.ScanAmCache.ToString().ToLower()};");
        sb.AppendLine($"config.ScanShimCache = {config.ScanShimCache.ToString().ToLower()};");
        sb.AppendLine($"config.ScanProcesses = {config.ScanProcesses.ToString().ToLower()};");
        sb.AppendLine($"config.ScanNetwork = {config.ScanNetwork.ToString().ToLower()};");
        sb.AppendLine($"config.ScanFileSystem = {config.ScanFileSystem.ToString().ToLower()};");
        sb.AppendLine($"config.ScanUSNJournal = {config.ScanUSNJournal.ToString().ToLower()};");
        sb.AppendLine($"config.ScanEventLogs = {config.ScanEventLogs.ToString().ToLower()};");
        sb.AppendLine($"config.ScanServices = {config.ScanServices.ToString().ToLower()};");
        sb.AppendLine($"config.ScanIntegrity = {config.ScanIntegrity.ToString().ToLower()};");
        sb.AppendLine($"config.ScanRecycleBin = {config.ScanRecycleBin.ToString().ToLower()};");
        sb.AppendLine($"config.ScanDNSCache = {config.ScanDNSCache.ToString().ToLower()};");
        sb.AppendLine($"config.ScanVPN = {config.ScanVPN.ToString().ToLower()};");
        sb.AppendLine($"config.ScanRegistry = {config.ScanRegistry.ToString().ToLower()};");
        sb.AppendLine($"config.ScanSRUM = {config.ScanSRUM.ToString().ToLower()};");
        sb.AppendLine($"config.ScanLSASS = {config.ScanLSASS.ToString().ToLower()};");
        sb.AppendLine($"config.ScanDrivers = {config.ScanDrivers.ToString().ToLower()};");
        sb.AppendLine($"config.ScanScheduledTasks = {config.ScanScheduledTasks.ToString().ToLower()};");
        sb.AppendLine($"config.ScanHostsFile = {config.ScanHostsFile.ToString().ToLower()};");
        sb.AppendLine($"config.ScanUSBHistory = {config.ScanUSBHistory.ToString().ToLower()};");
        sb.AppendLine($"config.ScanJumplists = {config.ScanJumplists.ToString().ToLower()};");
        sb.AppendLine($"config.ScanPcaClient = {config.ScanPcaClient.ToString().ToLower()};");
        sb.AppendLine($"config.ScanLoadedModules = {config.ScanLoadedModules.ToString().ToLower()};");
        sb.AppendLine($"config.ScanDeletedFiles = {config.ScanDeletedFiles.ToString().ToLower()};");
        sb.AppendLine($"config.DeletedFileMinutes = {config.DeletedFileMinutes};");
        sb.AppendLine($"config.ShowAllDeletedFiles = {config.ShowAllDeletedFiles.ToString().ToLower()};");
        sb.AppendLine($"config.PrefetchTimeMinutes = {config.PrefetchTimeMinutes};");
        sb.AppendLine($"config.MaxBrowserDays = {config.MaxBrowserDays};");
        sb.AppendLine($"config.SilentMode = {config.SilentMode.ToString().ToLower()};");
        sb.AppendLine($"config.IncludeHiddenUrls = {config.IncludeHiddenUrls.ToString().ToLower()};");
        sb.AppendLine($"config.DetectDeletedHistory = {config.DetectDeletedHistory.ToString().ToLower()};");
        sb.AppendLine($"config.EnableAiAnalysis = {config.EnableAiAnalysis.ToString().ToLower()};");
        return sb.ToString();
    }

    private static string GenerateProjectFile(string? sharedProjectPath)
    {
        var refPath = sharedProjectPath ?? "..\\Ilac.Shared\\Ilac.Shared.csproj";
        return $$"""
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>AntivirusuKapatin</AssemblyName>
    <ApplicationIcon>app.ico</ApplicationIcon>
    <PublishSingleFile>true</PublishSingleFile>
    <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <Optimize>true</Optimize>
    <ApplicationManifest>app.manifest</ApplicationManifest>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Data.Sqlite" Version="9.0.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.4" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="{{refPath}}" />
  </ItemGroup>
</Project>
""";
    }
}
