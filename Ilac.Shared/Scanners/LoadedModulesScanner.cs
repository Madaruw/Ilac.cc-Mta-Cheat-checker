using System.Diagnostics;
using System.Runtime.InteropServices;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class LoadedModulesScanner
{
    // System DLL names that are ONLY suspicious when loaded into game processes.
    // In browsers/media players/etc. these are legitimate Windows components.
    private static readonly HashSet<string> GameOnlyModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "dxgi.dll", "d3d9.dll", "d3d10.dll", "d3d11.dll", "d3d12.dll",
        "dinput8.dll", "dinput.dll", "dsound.dll", "ddraw.dll",
        "d3dcompiler_43.dll", "d3dcompiler_47.dll", "d3dcompiler_50.dll",
        "opengl32.dll",
    };

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanLoadedModules) return results;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var proc in Process.GetProcesses())
        {
            if (proc.Id == 0) continue;
            var procName = proc.ProcessName + ".exe";
            try
            {
                if (KnownCheats.IsSystemProcess(procName)) continue;
            }
            catch { }

            bool isGame = KnownCheats.GameProcesses.Contains(procName);

            var modules = EnumModules(proc.Id);
            foreach (var mod in modules)
            {
                try
                {
                    var modName = Path.GetFileName(mod);
                    if (string.IsNullOrEmpty(modName)) continue;
                    var lower = modName.ToLower();

                    // Always skip known-legitimate files
                    if (KnownCheats.IsLegitimateFile(modName)) continue;
                    if (KnownCheats.IsAntiCheatTool(modName)) continue;

                    // System DLL names (dxgi, d3d9, etc.) are only suspicious in games
                    if (!isGame && GameOnlyModules.Contains(lower))
                        continue;

                    string? reason = null;

                    // Only exact match against known cheat modules — NO pattern matching
                    // (pattern matching causes false positives like loader.dll, d3d9.dll)
                    if (KnownCheats.CheatModules.TryGetValue(lower, out var cheatReason))
                    {
                        // For non-game processes, skip game-only module names even if in CheatModules
                        if (!isGame && GameOnlyModules.Contains(lower))
                            continue;
                        reason = cheatReason;
                    }

                    if (reason == null) continue;

                    var key = $"{proc.ProcessName}:{lower}";
                    if (!seen.Add(key)) continue;

                    results.Add(new FileEntry
                    {
                        Name = modName,
                        Path = mod,
                        Source = $"Loaded Module ({proc.ProcessName}.exe)",
                        IsSuspicious = true,
                        Reason = reason!
                    });
                }
                catch { }
            }
        }

        return results;
    }

    private List<string> EnumModules(int pid)
    {
        var modules = new List<string>();
        const uint flags = NativeMethods.TH32CS_SNAPMODULE | NativeMethods.TH32CS_SNAPMODULE32;
        var snap = NativeMethods.CreateToolhelp32Snapshot(flags, (uint)pid);
        if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return modules;

        try
        {
            var me = new NativeMethods.MODULEENTRY32W
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.MODULEENTRY32W>()
            };

            if (NativeMethods.Module32FirstW(snap, ref me))
            {
                do
                {
                    var exePath = me.szExePath;
                    var modName = me.szModule;
                    if (!string.IsNullOrEmpty(exePath))
                        modules.Add(exePath!);
                    else if (!string.IsNullOrEmpty(modName))
                        modules.Add(modName!);
                }
                while (NativeMethods.Module32NextW(snap, ref me));
            }
        }
        catch { }
        finally
        {
            NativeMethods.CloseHandle(snap);
        }

        return modules;
    }
}
