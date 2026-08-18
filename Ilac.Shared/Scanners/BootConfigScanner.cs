using System.Diagnostics;
using System.Text;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class BootConfigScanner
{
    public List<Detection> Scan(ScanConfig config)
    {
        var results = new List<Detection>();
        if (!config.ScanIntegrity) return results;

        results.AddRange(CheckSecureBoot());
        results.AddRange(CheckBootSequence());
        results.AddRange(CheckHVCI());
        results.AddRange(CheckDMAProtection());

        return results;
    }

    private List<Detection> CheckSecureBoot()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("powershell", "-Command \"Confirm-SecureBootUEFI\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd().Trim();
            var errors = proc.StandardError.ReadToEnd().Trim();
            proc.WaitForExit(3000);

            if (output.Equals("False", StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new Detection
                {
                    Category = "Boot Security",
                    Name = "Secure Boot Disabled",
                    Detail = "Secure Boot is disabled - allows unsigned bootloaders/kernel code",
                    Severity = 5
                });
            }
        }
        catch
        {
            // Secure Boot check may fail on legacy BIOS systems - not suspicious
        }
        return results;
    }

    private List<Detection> CheckHVCI()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("powershell",
                "-Command \"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty VirtualizationBasedSecurityStatus\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(5000);

            if (output == "0" || output == "1")
            {
                results.Add(new Detection
                {
                    Category = "Boot Security",
                    Name = "HVCI/VBS Not Active",
                    Detail = "Virtualization-based security is not running - kernel is more vulnerable to driver-based cheats",
                    Severity = 3
                });
            }
        }
        catch { }
        return results;
    }

    private List<Detection> CheckDMAProtection()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("powershell",
                "-Command \"(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).DMAProtection\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(3000);

            if (output == "0" || output.Equals("False", StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new Detection
                {
                    Category = "Hardware Security",
                    Name = "DMA Protection Disabled",
                    Detail = "Kernel DMA protection is disabled - system is vulnerable to DMA attacks (PCILeech, DMA cheats)",
                    Severity = 6
                });
            }
        }
        catch { }
        return results;
    }

    private List<Detection> CheckBootSequence()
    {
        var results = new List<Detection>();
        try
        {
            var psi = new ProcessStartInfo("bcdedit", "/enum")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // Parse bcdedit output carefully - look for specific entries
            var sections = output.Split(new[] { "-------------------" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var section in sections)
            {
                var lines = section.Split('\n', StringSplitOptions.RemoveEmptyEntries);

                // Check for testsigning
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i].Trim();

                    if (line.Contains("testsigning", StringComparison.OrdinalIgnoreCase))
                    {
                        // Look for "Yes" on same line or next line
                        if (line.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new Detection
                            {
                                Category = "Boot Config",
                                Name = "Test Signing Mode Enabled",
                                Detail = "Test signing is ON - unsigned kernel drivers can be loaded",
                                Severity = 8
                            });
                        }
                    }

                    if (line.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase))
                    {
                        if (line.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new Detection
                            {
                                Category = "Boot Config",
                                Name = "Code Integrity Checks Disabled",
                                Detail = "Integrity checks are OFF - kernel tampering possible",
                                Severity = 7
                            });
                        }
                    }

                    if (line.Contains("debug", StringComparison.OrdinalIgnoreCase) &&
                        !line.Contains("debugger", StringComparison.OrdinalIgnoreCase))
                    {
                        if (line.Contains("Yes", StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new Detection
                            {
                                Category = "Boot Config",
                                Name = "Kernel Debugging Enabled",
                                Detail = "Windows kernel debugging is enabled - allows kernel memory access",
                                Severity = 7
                            });
                        }
                    }
                }
            }
        }
        catch { }
        return results;
    }
}
