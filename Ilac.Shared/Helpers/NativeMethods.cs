using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Ilac.Shared.Helpers;

public static class NativeMethods
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    private static Dictionary<string, string>? _deviceToDriveCache;

    public static Dictionary<string, string> GetDeviceToDriveMap()
    {
        if (_deviceToDriveCache != null) return _deviceToDriveCache;
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var letter = drive.Name.TrimEnd('\\', '/');
                if (string.IsNullOrEmpty(letter)) continue;
                var sb = new StringBuilder(260);
                if (QueryDosDevice(letter, sb, sb.Capacity) > 0)
                {
                    var device = sb.ToString();
                    if (!string.IsNullOrEmpty(device))
                        map[device] = letter;
                }
            }
        }
        catch { }
        _deviceToDriveCache = map;
        return map;
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string GetWindowsVersion()
    {
        try
        {
            var reg = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (reg != null)
            {
                var productName = reg.GetValue("ProductName")?.ToString() ?? "";
                var releaseId = reg.GetValue("ReleaseId")?.ToString() ?? "";
                var currentBuild = reg.GetValue("CurrentBuild")?.ToString() ?? "";
                var ubr = reg.GetValue("UBR")?.ToString() ?? "";
                return $"{productName} Build {currentBuild}.{ubr}";
            }
        }
        catch { }
        return Environment.OSVersion.ToString();
    }

    public static DateTime ChromeTimeToDateTime(long chromeTime)
    {
        if (chromeTime <= 0) return DateTime.MinValue;
        try
        {
            return DateTime.FromFileTimeUtc(chromeTime * 10);
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    public static DateTime FirefoxTimeToDateTime(long firefoxTime)
    {
        if (firefoxTime <= 0) return DateTime.MinValue;
        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(firefoxTime / 1000000).UtcDateTime;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    public static string GetMachineName() => Environment.MachineName;
    public static string GetUserName() => Environment.UserName;

    public static IEnumerable<string> GetAllUsers()
    {
        var usersDir = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
        if (!Directory.Exists(usersDir)) yield break;
        foreach (var dir in Directory.GetDirectories(usersDir))
        {
            var name = Path.GetFileName(dir);
            if (name is not ("Public" or "Default" or "Default User" or "All Users" or "desktop.ini"))
                yield return name;
        }
    }

    enum TOKEN_INFORMATION_CLASS
    {
        TokenElevation = 20
    }
}
