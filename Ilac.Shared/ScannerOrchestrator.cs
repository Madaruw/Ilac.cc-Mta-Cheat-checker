using Ilac.Shared.Helpers;
using Ilac.Shared.Models;
using Ilac.Shared.Scanners;
using Ilac.Shared.Services;

namespace Ilac.Shared;

public class ScannerOrchestrator
{
    private readonly BrowserHistoryScanner _browserScanner = new();
    private readonly PrefetchScanner _prefetchScanner = new();
    private readonly BAMScanner _bamScanner = new();
    private readonly AmCacheScanner _amCacheScanner = new();
    private readonly ShimCacheScanner _shimCacheScanner = new();
    private readonly ProcessScanner _processScanner = new();
    private readonly NetworkScanner _networkScanner = new();
    private readonly FileSystemScanner _fileSystemScanner = new();
    private readonly ServiceScanner _serviceScanner = new();
    private readonly IntegrityScanner _integrityScanner = new();
    private readonly RegistryScanner _registryScanner = new();
    private readonly EventLogScanner _eventLogScanner = new();
    private readonly DriversScanner _driversScanner = new();
    private readonly BootConfigScanner _bootConfigScanner = new();
    private readonly USNJournalScanner _usnJournalScanner = new();
    private readonly ScheduledTasksScanner _scheduledTasksScanner = new();
    private readonly HostsFileScanner _hostsFileScanner = new();
    private readonly USBHistoryScanner _usbHistoryScanner = new();
    private readonly JumplistScanner _jumplistScanner = new();
    private readonly PcaClientScanner _pcaClientScanner = new();
    private readonly FullDiskScanner _fullDiskScanner = new();
    private readonly LoadedModulesScanner _loadedModulesScanner = new();
    private readonly BinaryScanner _binaryScanner = new();
    private readonly ScoringService _scoringService = new();
    private readonly SummaryService _summaryService = new();

    public async Task<ScanResult> RunFullScan(ScanConfig config, IProgress<(string stage, int percent)>? progress = null)
    {
        var result = new ScanResult
        {
            MachineName = Environment.MachineName,
            UserName = Environment.UserName,
            WindowsVersion = NativeMethods.GetWindowsVersion(),
            ScanTime = DateTime.UtcNow
        };

        var totalScanners = 20;
        var completed = 0;
        var lockObj = new object();

        void Report(string stage)
        {
            lock (lockObj) { completed++; }
            var pct = (int)((double)completed / totalScanners * 100);
            progress?.Report((stage, Math.Min(pct, 99)));
        }

        var scanTasks = new List<Task>();

        scanTasks.Add(Task.Run(() => {
            try { result.BrowserHistory = _browserScanner.Scan(config); }
            catch { }
            Report("Browser History"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_prefetchScanner.Scan(config)); Report("Prefetch"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_bamScanner.Scan(config)); Report("BAM"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_amCacheScanner.Scan(config)); Report("AmCache"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_shimCacheScanner.Scan(config)); Report("ShimCache"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousProcesses = _processScanner.Scan(config); Report("Processes"); }));
        scanTasks.Add(Task.Run(() => { result.NetworkConnections = _networkScanner.Scan(config); Report("Network"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_fileSystemScanner.Scan(config)); Report("File System"); }));
        scanTasks.Add(Task.Run(() => { result.DeletedFiles.AddRange(_fileSystemScanner.ScanDeleted(config)); Report("Recycle Bin"); }));
        scanTasks.Add(Task.Run(() => { result.BypassAttempts.AddRange(_serviceScanner.Scan(config)); Report("Services"); }));
        scanTasks.Add(Task.Run(() => { result.BypassAttempts.AddRange(_integrityScanner.Scan(config)); Report("Integrity"); }));
        scanTasks.Add(Task.Run(() => { result.RegistryEntries = _registryScanner.Scan(config); Report("Registry"); }));
        scanTasks.Add(Task.Run(() => { result.Detections.AddRange(_eventLogScanner.Scan(config)); Report("Event Logs"); }));
        scanTasks.Add(Task.Run(() => { result.Detections.AddRange(_driversScanner.Scan(config)); Report("Drivers"); }));
        scanTasks.Add(Task.Run(() => { result.Detections.AddRange(_bootConfigScanner.Scan(config)); Report("Boot Config"); }));
        scanTasks.Add(Task.Run(() => { result.DeletedFiles.AddRange(_usnJournalScanner.Scan(config)); Report("USN Journal"); }));
        scanTasks.Add(Task.Run(() => { result.Detections.AddRange(_scheduledTasksScanner.Scan(config)); Report("Scheduled Tasks"); }));
        scanTasks.Add(Task.Run(() => { result.Detections.AddRange(_hostsFileScanner.Scan(config)); Report("Hosts File"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_fullDiskScanner.Scan(config)); Report("Full Disk"); }));
        scanTasks.Add(Task.Run(() => { result.SuspiciousFiles.AddRange(_loadedModulesScanner.Scan(config)); Report("Loaded Modules"); }));

        // Wait for all tasks, but max 120 seconds
        var allDone = Task.WhenAll(scanTasks);
        var timeoutTask = Task.Delay(TimeSpan.FromSeconds(120));
        await Task.WhenAny(allDone, timeoutTask);

        // Collect recently executed programs from Prefetch
        try
        {
            result.RecentlyExecuted = _prefetchScanner.GetRecentFiles(config.PrefetchTimeMinutes)
                .Where(n => !KnownCheats.IsSystemProcess(n + ".exe") && !KnownCheats.IsLegitimateFile(n + ".exe"))
                .Distinct()
                .Take(50)
                .ToList();
        }
        catch { }

        // Collect loaded drivers
        try { result.LoadedDrivers = _driversScanner.GetLoadedDrivers(); } catch { }

        // USN Journal cleared check
        try
        {
            if (_usnJournalScanner.IsJournalCleared(config))
            {
                result.BypassAttempts.Add(new BypassEntry
                {
                    Type = "USN Journal Cleared",
                    Detail = "NTFS USN Change Journal has been deleted or cleared - file activity history wiped",
                    Severity = 8
                });
            }
        }
        catch { }

        // Separate MTA-specific cheats from general suspicious files
        foreach (var f in result.SuspiciousFiles.Where(f => f.IsSuspicious))
        {
            if (KnownCheats.IsMtaCheat(f.Name, f.Source, f.Reason))
                result.MtaSpecificCheats.Add(f);
        }

        // Binary scan — search for MTA cheat strings inside .exe/.dll files
        try
        {
            var binaryResults = _binaryScanner.ScanSuspiciousFiles(result.SuspiciousFiles, config);
            result.SuspiciousFiles.AddRange(binaryResults);
            foreach (var b in binaryResults)
                result.MtaSpecificCheats.Add(b);
        }
        catch { }

        // Score first so the summary verdict reflects the real score.
        result = _scoringService.CalculateScore(result);
        result.Summary = _summaryService.GenerateSummary(result);

        progress?.Report(("Finalizing", 100));

        // AI analysis via Groq
        if (config.EnableAiAnalysis && !string.IsNullOrEmpty(config.GroqApiKey))
        {
            try
            {
                progress?.Report(("AI Analysis", 100));
                var groq = new GroqService();
                result.AiAnalysis = await groq.AnalyzeScanResult(config.GroqApiKey, result);
                result.AiQuotaExceeded = groq.QuotaExceeded;
                result.AiConnected = !string.IsNullOrEmpty(result.AiAnalysis);

                // Send quota exceeded message to Discord if confirmed
                if (string.IsNullOrEmpty(result.AiAnalysis) && groq.QuotaExceeded)
                {
                    var webhook = new WebhookService();
                    await webhook.SendQuotaExceeded(config.WebhookUrl);
                }
            }
            catch { }
        }

        // Send results to webhook
        if (!string.IsNullOrEmpty(config.WebhookUrl) && config.OutputFormat == "webhook")
        {
            var webhook = new WebhookService();
            await webhook.SendResult(config.WebhookUrl, result);
        }

        return result;
    }
}
