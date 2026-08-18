namespace Ilac.Shared.Models;

public class ScanConfig
{
    public string WebhookUrl { get; set; } = "";
    public int PrefetchTimeMinutes { get; set; } = 30;
    public bool ScanBrowserHistory { get; set; } = true;
    public bool ScanPrefetch { get; set; } = true;
    public bool ScanBAM { get; set; } = true;
    public bool ScanAmCache { get; set; } = true;
    public bool ScanShimCache { get; set; } = true;
    public bool ScanProcesses { get; set; } = true;
    public bool ScanNetwork { get; set; } = true;
    public bool ScanFileSystem { get; set; } = true;
    public bool ScanUSNJournal { get; set; } = true;
    public bool ScanDeletedFiles { get; set; } = true;
    public int DeletedFileMinutes { get; set; } = 120;
    public bool ShowAllDeletedFiles { get; set; } = true;
    public bool ScanEventLogs { get; set; } = true;
    public bool ScanServices { get; set; } = true;
    public bool ScanIntegrity { get; set; } = true;
    public bool ScanRecycleBin { get; set; } = true;
    public bool ScanDNSCache { get; set; } = true;
    public bool ScanVPN { get; set; } = true;
    public bool ScanRegistry { get; set; } = true;
    public bool ScanMFT { get; set; } = true;
    public bool ScanSRUM { get; set; } = true;
    public bool ScanLSASS { get; set; } = true;
    public bool ScanDrivers { get; set; } = true;
    public bool ScanStartup { get; set; } = true;
    public bool ScanScheduledTasks { get; set; } = true;
    public bool ScanHostsFile { get; set; } = true;
    public bool ScanUSBHistory { get; set; } = true;
    public bool ScanJumplists { get; set; } = true;
    public bool ScanPcaClient { get; set; } = true;
    public bool ScanLoadedModules { get; set; } = true;
    public List<string> CustomKeywords { get; set; } = new();
    public int MaxBrowserDays { get; set; } = 30;
    public bool IncludeHiddenUrls { get; set; } = false;
    public bool DetectDeletedHistory { get; set; } = true;
    public bool ShowSummaryOnly { get; set; } = false;
    public bool SilentMode { get; set; } = true;
    public string OutputFormat { get; set; } = "webhook";
    public string GroqApiKey { get; set; } = "";
    public bool EnableAiAnalysis { get; set; } = true;
}
