namespace Ilac.Shared.Models;

public class ScanResult
{
    public string MachineName { get; set; } = "";
    public string UserName { get; set; } = "";
    public string WindowsVersion { get; set; } = "";
    public DateTime ScanTime { get; set; } = DateTime.UtcNow;
    public int TotalScore { get; set; }
    public int MaxScore { get; set; } = 10;
    public List<Detection> Detections { get; set; } = new();
    public List<BrowserHistoryEntry> BrowserHistory { get; set; } = new();
    public List<ProcessEntry> SuspiciousProcesses { get; set; } = new();
    public List<FileEntry> SuspiciousFiles { get; set; } = new();
    public List<NetworkEntry> NetworkConnections { get; set; } = new();
    public List<BypassEntry> BypassAttempts { get; set; } = new();
    public List<RegistryEntry> RegistryEntries { get; set; } = new();
    public List<FileEntry> DeletedFiles { get; set; } = new();
    public List<FileEntry> MtaSpecificCheats { get; set; } = new();
    public List<string> RecentlyExecuted { get; set; } = new();
    public List<string> LoadedDrivers { get; set; } = new();
    public string AiAnalysis { get; set; } = "";
    public bool AiQuotaExceeded { get; set; }
    public bool AiConnected { get; set; }
    public Summary Summary { get; set; } = new();
}

public class Detection
{
    public string Category { get; set; } = "";
    public string Name { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Severity { get; set; }
    public DateTime? Timestamp { get; set; }
}

public class BrowserHistoryEntry
{
    public string Browser { get; set; } = "";
    public string Url { get; set; } = "";
    public string Title { get; set; } = "";
    public DateTime LastVisitTime { get; set; }
    public int VisitCount { get; set; }
    public bool IsSuspicious { get; set; }
    public string MatchReason { get; set; } = "";
}

public class ProcessEntry
{
    public string ProcessName { get; set; } = "";
    public int PID { get; set; }
    public string ParentProcess { get; set; } = "";
    public string WindowTitle { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = "";
}

public class FileEntry
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTime? CreationTime { get; set; }
    public DateTime? LastModifiedTime { get; set; }
    public DateTime? LastExecutionTime { get; set; }
    public long Size { get; set; }
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = "";
    public string Source { get; set; } = "";
}

public class NetworkEntry
{
    public string Type { get; set; } = "";
    public string Detail { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = "";
}

public class BypassEntry
{
    public string Type { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Severity { get; set; }
}

public class RegistryEntry
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
    public string Data { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = "";
}

public class Summary
{
    public string Verdict { get; set; } = "Temiz";
    public int TotalDetections { get; set; }
    public int HighSeverityCount { get; set; }
    public int MediumSeverityCount { get; set; }
    public int LowSeverityCount { get; set; }
    public string Explanation { get; set; } = "";
    public List<string> FoundCheatNames { get; set; } = new();
    public List<string> FoundCategories { get; set; } = new();
    public Dictionary<string, string> FileExplanations { get; set; } = new();
}
