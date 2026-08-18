using System.Diagnostics;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class ScheduledTasksScanner
{
    public List<Detection> Scan(ScanConfig config)
    {
        var results = new List<Detection>();
        if (!config.ScanScheduledTasks) return results;

        try
        {
            var psi = new ProcessStartInfo("schtasks", "/query /fo CSV /nh")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            proc.WaitForExit(5000); // 5 sec max
            if (!proc.HasExited) { try { proc.Kill(); } catch { } return results; }
            var output = proc.StandardOutput.ReadToEnd();

            var csvLines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in csvLines.Skip(1))
            {
                try
                {
                    var fields = ParseCsvLine(line);
                    if (fields.Length < 8) continue;

                    var taskName = fields[0]?.Trim('"') ?? "";
                    var taskToRun = fields[7]?.Trim('"') ?? "";

                    if (string.IsNullOrEmpty(taskToRun)) continue;

                    var lower = taskToRun.ToLower();

                    bool suspicious = false;
                    string reason = "";

                    if (lower.Contains(@"\temp\") || lower.Contains(@"\tmp\"))
                    {
                        suspicious = true;
                        reason = "Scheduled task running from temp directory";
                    }
                    else if (lower.Contains(@"\downloads\"))
                    {
                        suspicious = true;
                        reason = "Scheduled task running from Downloads directory";
                    }

                    if (!suspicious)
                    {
                        foreach (var cheat in KnownCheats.CheatProcesses)
                        {
                            if (lower.Contains(cheat.Key.ToLower()))
                            {
                                suspicious = true;
                                reason = $"Scheduled task references known cheat: {cheat.Value}";
                                break;
                            }
                        }
                    }

                    if (!suspicious)
                    {
                        foreach (var tool in KnownCheats.SuspiciousTools)
                        {
                            if (lower.Contains(tool.Key.ToLower()))
                            {
                                suspicious = true;
                                reason = $"Scheduled task references suspicious tool: {tool.Value}";
                                break;
                            }
                        }
                    }

                    if (!suspicious && lower.Contains("powershell") &&
                        (lower.Contains("-enc") || lower.Contains("-encodedcommand") ||
                         lower.Contains("downloadstring") || lower.Contains("invoke-expression")))
                    {
                        suspicious = true;
                        reason = "Scheduled task uses suspicious PowerShell command";
                    }

                    if (suspicious)
                    {
                        results.Add(new Detection
                        {
                            Category = "Scheduled Task",
                            Name = $"Suspicious Task: {taskName}",
                            Detail = $"{reason} - Command: {taskToRun.Substring(0, Math.Min(200, taskToRun.Length))}",
                            Severity = 7
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        return results;
    }

    private static string[] ParseCsvLine(string line)
    {
        var result = new List<string>();
        bool inQuotes = false;
        var current = new System.Text.StringBuilder();
        foreach (var c in line)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (c == ',' && !inQuotes) { result.Add(current.ToString()); current.Clear(); continue; }
            current.Append(c);
        }
        result.Add(current.ToString());
        return result.ToArray();
    }
}
