using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class ShimCacheScanner
{
    private static readonly string ShimCacheRegPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

    // Win10/11 entry signature "00ts" (bytes 0x30 0x30 0x74 0x73)
    private static readonly byte[] EntrySig = { 0x30, 0x30, 0x74, 0x73 };

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanShimCache) return results;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ShimCacheRegPath);
            if (key == null) return results;

            var value = key.GetValue("AppCompatCache") ?? key.GetValue("AppCompatCacheEntry");
            if (value is not byte[] data) return results;

            var entries = ParseWin10(data);
            results.AddRange(entries.Where(e => e.IsSuspicious));
        }
        catch { }

        return results;
    }

    private List<FileEntry> ParseWin10(byte[] data)
    {
        var results = new List<FileEntry>();
        try
        {
            if (data.Length < 12) return results;

            // Scan for entry signatures so we tolerate header/version differences.
            int i = 0;
            while (i + 8 < data.Length)
            {
                if (!MatchSig(data, i)) { i++; continue; }

                try
                {
                    var entrySize = BitConverter.ToUInt32(data, i + 4);
                    if (entrySize == 0 || entrySize > data.Length - i)
                    { i += 4; continue; }

                    if (i + 10 > data.Length) break;
                    var pathLen = BitConverter.ToUInt16(data, i + 8);
                    var pathStart = i + 10;

                    if (pathLen <= 0 || pathLen > 2048 || pathStart + pathLen > data.Length)
                    { i += 8 + (int)entrySize; continue; }

                    var path = System.Text.Encoding.Unicode.GetString(data, pathStart, pathLen).Trim('\0');

                    // Try to read last-modified FILETIME right after the path.
                    DateTime? lastMod = null;
                    var tsStart = pathStart + pathLen;
                    if (tsStart + 8 <= data.Length)
                    {
                        try
                        {
                            var ft = BitConverter.ToInt64(data, tsStart);
                            if (ft > 0) lastMod = DateTime.FromFileTimeUtc(ft);
                        }
                        catch { }
                    }

                    if (!string.IsNullOrEmpty(path) && path.Contains("\\"))
                    {
                        var fileName = Path.GetFileName(path);
                        var lower = fileName.ToLower();
                        var entry = new FileEntry
                        {
                            Name = fileName,
                            Path = path,
                            Source = "ShimCache",
                            LastModifiedTime = lastMod,
                            LastExecutionTime = lastMod
                        };

                        if (KnownCheats.CheatProcesses.TryGetValue(lower, out var reason))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = reason;
                        }
                        else if (KnownCheats.SuspiciousTools.TryGetValue(lower, out var toolReason))
                        {
                            entry.IsSuspicious = true;
                            entry.Reason = toolReason;
                        }
                        else
                        {
                            if (!KnownCheats.IsLegitimateFile(fileName) && !KnownCheats.IsAntiCheatTool(fileName))
                            {
                                foreach (var pattern in KnownCheats.CheatFilePatterns)
                                {
                                    var matchStr = pattern.Replace("*", "").ToLower();
                                    if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                                    {
                                        entry.IsSuspicious = true;
                                        entry.Reason = $"Matches suspicious pattern: {pattern}";
                                        break;
                                    }
                                }
                            }
                        }

                        results.Add(entry);
                    }

                    // Jump past this entry's body. Fall back to signature scanning if size looks off.
                    var next = i + 8 + (int)entrySize;
                    i = next > i ? next : i + 4;
                }
                catch { i += 4; }
            }
        }
        catch { }
        return results;
    }

    private static bool MatchSig(byte[] data, int offset)
    {
        return data[offset] == EntrySig[0] && data[offset + 1] == EntrySig[1] &&
               data[offset + 2] == EntrySig[2] && data[offset + 3] == EntrySig[3];
    }
}
