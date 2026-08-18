namespace Ilac.Shared.Helpers;

public static class BrowserPaths
{
    public static readonly Dictionary<string, BrowserInfo> SupportedBrowsers = new()
    {
        ["Chrome"] = new BrowserInfo
        {
            HistoryPath = @"Google\Chrome\User Data\Default\History",
            ProfilePath = @"Google\Chrome\User Data",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true
        },
        ["Edge"] = new BrowserInfo
        {
            HistoryPath = @"Microsoft\Edge\User Data\Default\History",
            ProfilePath = @"Microsoft\Edge\User Data",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true
        },
        ["Brave"] = new BrowserInfo
        {
            HistoryPath = @"BraveSoftware\Brave-Browser\User Data\Default\History",
            ProfilePath = @"BraveSoftware\Brave-Browser\User Data",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true
        },
        ["Opera"] = new BrowserInfo
        {
            HistoryPath = @"Opera Software\Opera Stable\Default\History",
            ProfilePath = @"Opera Software\Opera Stable\Default",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true,
            UseAppDataRoaming = true
        },
        ["Opera GX"] = new BrowserInfo
        {
            HistoryPath = @"Opera Software\Opera GX Stable\Default\History",
            ProfilePath = @"Opera Software\Opera GX Stable\Default",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true,
            UseAppDataRoaming = true
        },
        ["Firefox"] = new BrowserInfo
        {
            HistoryPath = @"Mozilla\Firefox\Profiles",
            ProfilePath = @"Mozilla\Firefox\Profiles",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_date FROM moz_places",
            KeywordQuery = "",
            TimestampMultiplier = 1,
            IsChromium = false,
            UseAppDataRoaming = true
        },
        ["Vivaldi"] = new BrowserInfo
        {
            HistoryPath = @"Vivaldi\User Data\Default\History",
            ProfilePath = @"Vivaldi\User Data",
            HistoryQuery = "SELECT url, title, visit_count, last_visit_time, hidden FROM urls",
            KeywordQuery = "SELECT term, url_id FROM keyword_search_terms",
            TimestampMultiplier = 1,
            IsChromium = true
        },
    };
}

public class BrowserInfo
{
    public string HistoryPath { get; set; } = "";
    public string ProfilePath { get; set; } = "";
    public string HistoryQuery { get; set; } = "";
    public string KeywordQuery { get; set; } = "";
    public double TimestampMultiplier { get; set; } = 1;
    public bool IsChromium { get; set; }
    public bool UseAppDataRoaming { get; set; }
    public bool UsesProfileFolder { get; set; }
}
