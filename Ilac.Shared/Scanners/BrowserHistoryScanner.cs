using Microsoft.Data.Sqlite;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class BrowserHistoryScanner
{
    private static readonly string LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    public List<BrowserHistoryEntry> Scan(ScanConfig config)
    {
        var results = new List<BrowserHistoryEntry>();
        if (!config.ScanBrowserHistory) return results;

        foreach (var browser in BrowserPaths.SupportedBrowsers)
        {
            try
            {
                if (browser.Key == "Firefox")
                {
                    results.AddRange(ScanFirefoxHistory(browser.Value, config));
                }
                else
                {
                    results.AddRange(ScanChromiumHistory(browser.Key, browser.Value, config));
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BrowserScanner] Error scanning {browser.Key}: {ex.Message}");
            }
        }

        Debug.WriteLine($"[BrowserScanner] Total suspicious entries: {results.Count}");
        return results;
    }

    private List<BrowserHistoryEntry> ScanChromiumHistory(string browserName, BrowserInfo info, ScanConfig config)
    {
        var results = new List<BrowserHistoryEntry>();
        var basePath = info.UseAppDataRoaming ? AppDataRoaming : LocalAppData;

        // Find all History files across profiles
        var historyFiles = new List<string>();
        var historyFile = Path.Combine(basePath, info.HistoryPath);
        if (File.Exists(historyFile))
            historyFiles.Add(historyFile);

        // Check other profiles (Profile 1, Profile 2, etc.)
        var profileDir = Path.GetDirectoryName(Path.GetDirectoryName(historyFile));
        if (profileDir != null && Directory.Exists(profileDir))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(profileDir, "Profile *"))
                {
                    var histFile = Path.Combine(dir, "History");
                    if (File.Exists(histFile) && !historyFiles.Contains(histFile))
                        historyFiles.Add(histFile);
                }
            }
            catch { }
        }

        foreach (var histFile in historyFiles)
        {
            results.AddRange(ScanSingleChromiumHistory(browserName, histFile, config));
        }

        return results;
    }

    private List<BrowserHistoryEntry> ScanSingleChromiumHistory(string browserName, string historyFile, ScanConfig config)
    {
        var results = new List<BrowserHistoryEntry>();
        string tempFile = CopyToTemp(historyFile);
        if (tempFile == null) return results;

        try
        {
            using var conn = new SqliteConnection($"Data Source={tempFile};Mode=ReadOnly");
            conn.Open();

            var cutoff = DateTime.UtcNow.AddDays(-config.MaxBrowserDays);

            // 1. Scan keyword_search_terms — LIMIT 200 for speed
            try
            {
                using var checkCmd = new SqliteCommand(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='keyword_search_terms'", conn);
                var tableExists = checkCmd.ExecuteScalar();

                if (tableExists != null)
                {
                    var keywordQuery = @"
                        SELECT kst.term, kst.url_id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
                        FROM keyword_search_terms kst
                        LEFT JOIN urls ON kst.url_id = urls.id
                        ORDER BY urls.last_visit_time DESC
                        LIMIT 200";

                    using var kwCmd = new SqliteCommand(keywordQuery, conn);
                    using var kwReader = kwCmd.ExecuteReader();

                    while (kwReader.Read())
                    {
                        try
                        {
                            var searchTerm = kwReader["term"]?.ToString() ?? "";
                            var url = kwReader["url"]?.ToString() ?? "";
                            var title = kwReader["title"]?.ToString() ?? "";
                            var visitCount = 0;
                            int.TryParse(kwReader["visit_count"]?.ToString(), out visitCount);

                            long rawTime = 0;
                            long.TryParse(kwReader["last_visit_time"]?.ToString(), out rawTime);
                            var lastVisit = NativeMethods.ChromeTimeToDateTime(rawTime);

                            // If no timestamp, still check it
                            if (lastVisit < cutoff && lastVisit > DateTime.MinValue) continue;

                            var isSuspicious = IsSuspiciousText(searchTerm, url, title, out var reason);

                            if (isSuspicious)
                            {
                                var entry = new BrowserHistoryEntry
                                {
                                    Browser = browserName,
                                    Url = $"Search: \"{searchTerm}\"",
                                    Title = title,
                                    LastVisitTime = lastVisit > DateTime.MinValue ? lastVisit : DateTime.UtcNow,
                                    VisitCount = visitCount,
                                    IsSuspicious = true,
                                    MatchReason = reason
                                };

                                if (!results.Any(r => r.MatchReason == reason))
                                    results.Add(entry);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BrowserScanner] keyword_search_terms error: {ex.Message}");
            }

            // 2. Scan urls table - check URLs and titles for suspicious content
            try
            {
                var urlQuery = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500";

                using var cmd = new SqliteCommand(urlQuery, conn);
                using var reader = cmd.ExecuteReader();

                while (reader.Read())
                {
                    try
                    {
                        var url = reader["url"]?.ToString() ?? "";
                        var title = reader["title"]?.ToString() ?? "";
                        var visitCount = 0;
                        int.TryParse(reader["visit_count"]?.ToString(), out visitCount);

                        long rawTime = 0;
                        long.TryParse(reader["last_visit_time"]?.ToString(), out rawTime);
                        var lastVisit = NativeMethods.ChromeTimeToDateTime(rawTime);

                        if (lastVisit < cutoff && lastVisit > DateTime.MinValue) continue;

                        var isSuspicious = IsSuspiciousText("", url, title, out var reason);

                        if (isSuspicious)
                        {
                            // Avoid duplicates
                            if (!results.Any(r => r.Url == url))
                            {
                                results.Add(new BrowserHistoryEntry
                                {
                                    Browser = browserName,
                                    Url = url,
                                    Title = title,
                                    LastVisitTime = lastVisit > DateTime.MinValue ? lastVisit : DateTime.UtcNow,
                                    VisitCount = visitCount,
                                    IsSuspicious = true,
                                    MatchReason = reason
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[BrowserScanner] urls scan error: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[BrowserScanner] SQLite connection error: {ex.Message}");
        }
        finally
        {
            CleanupTemp(tempFile);
        }

        return results;
    }

    private List<BrowserHistoryEntry> ScanFirefoxHistory(BrowserInfo info, ScanConfig config)
    {
        var results = new List<BrowserHistoryEntry>();
        var profilesDir = Path.Combine(AppDataRoaming, info.HistoryPath);

        if (!Directory.Exists(profilesDir)) return results;

        foreach (var profileDir in Directory.GetDirectories(profilesDir, "*.default*"))
        {
            var placesFile = Path.Combine(profileDir, "places.sqlite");
            if (!File.Exists(placesFile)) continue;

            string tempFile = CopyToTemp(placesFile);
            if (tempFile == null) continue;

            try
            {
                using var conn = new SqliteConnection($"Data Source={tempFile};Mode=ReadOnly");
                conn.Open();

                var cutoff = DateTime.UtcNow.AddDays(-config.MaxBrowserDays);

                try
                {
                    using var cmd = new SqliteCommand(
                        @"SELECT p.url, p.title, p.visit_count, p.last_visit_date
                          FROM moz_places p
                          WHERE p.last_visit_date > 0
                          ORDER BY p.last_visit_date DESC", conn);
                    using var reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        try
                        {
                            var url = reader["url"]?.ToString() ?? "";
                            var title = reader["title"]?.ToString() ?? "";
                            var visitCount = 0;
                            int.TryParse(reader["visit_count"]?.ToString(), out visitCount);
                            var rawTime = Convert.ToInt64(reader["last_visit_date"]);
                            var lastVisit = NativeMethods.FirefoxTimeToDateTime(rawTime);

                            if (lastVisit < cutoff) continue;

                            var isSuspicious = IsSuspiciousText("", url, title, out var reason);
                            if (isSuspicious)
                            {
                                results.Add(new BrowserHistoryEntry
                                {
                                    Browser = "Firefox",
                                    Url = url,
                                    Title = title,
                                    LastVisitTime = lastVisit,
                                    VisitCount = visitCount,
                                    IsSuspicious = true,
                                    MatchReason = reason
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
            catch { }
            finally
            {
                CleanupTemp(tempFile);
            }
        }

        return results;
    }

    private bool IsSuspiciousText(string searchTerm, string url, string title, out string reason)
    {
        reason = "";

        var decodedUrl = UrlDecode(url);
        var combined = $"{searchTerm} {decodedUrl} {title}".ToLower().Trim();

        if (string.IsNullOrWhiteSpace(combined)) return false;

        // ONLY match MTA-specific keywords — not generic "hack", "cheat", "trainer", "crack"
        // This prevents false positives from news articles, game pages, etc.
        foreach (var kw in KnownCheats.CheatKeywords)
        {
            // Only match if the keyword is MTA-specific (contains "mta" or known brand)
            var keyLower = kw.Key.ToLower();
            bool isMtaSpecific = keyLower.Contains("mta") || keyLower.Contains("mtasa") ||
                                  keyLower.Contains("multitheftauto") || keyLower.Contains("gasmask") ||
                                  keyLower.Contains("sobfox") || keyLower.Contains("nexida") ||
                                  keyLower.Contains("exterium") || keyLower.Contains("capyprivate") ||
                                  keyLower.Contains("deadlyteam") || keyLower.Contains("hydrogen") ||
                                  keyLower.Contains("franny") || keyLower.Contains("speedi") ||
                                  keyLower.Contains("shine") || keyLower.Contains("s0beit") ||
                                  keyLower.Contains("neutrino") || keyLower.Contains("exelans") ||
                                  keyLower.Contains("eclipso") || keyLower.Contains("phantomcheat") ||
                                  keyLower.Contains("scriptware") || keyLower.Contains("superspoofer") ||
                                  keyLower.Contains("keyauth") || keyLower.Contains("eauth") ||
                                  keyLower.Contains("napse") || keyLower.Contains("ocean.ac") ||
                                  keyLower.Contains("anticheat.ac") || keyLower.Contains("detect.ac") ||
                                  keyLower.Contains("unknowncheats") || keyLower.Contains("ugbase") ||
                                  keyLower.Contains("cheatermad") || keyLower.Contains("crazycapy") ||
                                  keyLower.Contains("mpgh") || keyLower.Contains("hackforums") ||
                                  keyLower.Contains("nulled.to") || keyLower.Contains("cracked.io") ||
                                  keyLower.Contains("leak.sx") || keyLower.Contains("sinfulsite") ||
                                  keyLower.Contains("fivem") || keyLower.Contains("rage mp") ||
                                  keyLower.Contains("altv") || keyLower.Contains("redm") ||
                                  keyLower.Contains("pcileech") || keyLower.Contains("kdmapper") ||
                                  keyLower.Contains("byovd") || keyLower.Contains("dma cheat") ||
                                  keyLower.Contains("kernel cheat") || keyLower.Contains("driver cheat") ||
                                  keyLower.Contains("moonloader") || keyLower.Contains("lua executor") ||
                                  keyLower.Contains("lua injector") || keyLower.Contains("cleo") ||
                                  keyLower.Contains("mtasacheats");

            if (!isMtaSpecific) continue;

            if (combined.Contains(keyLower))
            {
                reason = kw.Value;
                return true;
            }
        }

        // Check suspicious domains — ONLY MTA-specific ones
        foreach (var domain in KnownCheats.SuspiciousDomains)
        {
            var d = domain.ToLower();
            // ONLY match if the domain is MTA-specific or a known cheat site
            bool isMtaRelated = d.Contains("mta") || d.Contains("mtasa") || d.Contains("multitheftauto") ||
                                d.Contains("gasmask") || d.Contains("sobfox") || d.Contains("nexida") ||
                                d.Contains("exterium") || d.Contains("capyprivate") || d.Contains("0xcheat") ||
                                d.Contains("deadlyteam") || d.Contains("hydrogen") || d.Contains("franny") ||
                                d.Contains("speedi") || d.Contains("shine") || d.Contains("s0beit") ||
                                d.Contains("neutrino") || d.Contains("exelans") || d.Contains("eclipso") ||
                                d.Contains("phantomcheat") || d.Contains("scriptware") || d.Contains("superspoofer") ||
                                d.Contains("keyauth") || d.Contains("eauth") || d.Contains("napse") ||
                                d.Contains("ocean.ac") || d.Contains("anticheat.ac") || d.Contains("detect.ac") ||
                                d.Contains("unknowncheats") || d.Contains("ugbase") || d.Contains("cheatermad") ||
                                d.Contains("crazycapy") || d.Contains("mpgh") || d.Contains("hackforums") ||
                                d.Contains("nulled.to") || d.Contains("cracked.io") || d.Contains("leak.sx") ||
                                d.Contains("sinfulsite") || d.Contains("mtasacheats") || d.Contains("fivemhack") ||
                                d.Contains("fivemcheat") || d.Contains("mta.club") || d.Contains("mta.dns") ||
                                d.Contains("kdmapper") || d.Contains("pcileech") || d.Contains("byovd") ||
                                d.Contains("mta hile") || d.Contains("mta hack") || d.Contains("mta cheat");
            if (!isMtaRelated) continue;

            if (combined.Contains(d))
            {
                reason = $"MTA suspicious domain: {domain}";
                return true;
            }
        }

        // Check custom keywords
        return false;
    }

    private static string UrlDecode(string url)
    {
        try
        {
            // Decode URL-encoded characters
            // Replace + with space (in query strings, + = space)
            var decoded = url.Replace("+", " ");
            decoded = Uri.UnescapeDataString(decoded);
            return decoded;
        }
        catch
        {
            return url;
        }
    }

    private static string? CopyToTemp(string source)
    {
        try
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "ilac_scan");
            Directory.CreateDirectory(tempDir);
            var tempFile = Path.Combine(tempDir, $"{Guid.NewGuid()}.db");
            // Use File.Open with FileShare to handle locked files
            using var src = File.Open(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var dst = File.Create(tempFile);
            src.CopyTo(dst);
            return tempFile;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[BrowserScanner] CopyToTemp error: {ex.Message}");
            return null;
        }
    }

    private static void CleanupTemp(string tempFile)
    {
        try { if (File.Exists(tempFile)) File.Delete(tempFile); }
        catch { }
    }
}
