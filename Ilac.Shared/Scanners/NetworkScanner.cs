using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Management;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class NetworkScanner
{
    public List<NetworkEntry> Scan(ScanConfig config)
    {
        var results = new List<NetworkEntry>();
        if (!config.ScanNetwork) return results;

        results.AddRange(ScanVPN());
        if (config.ScanDNSCache) results.AddRange(ScanDNSCache());

        return results;
    }

    private List<NetworkEntry> ScanVPN()
    {
        var results = new List<NetworkEntry>();
        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var adapter in adapters)
            {
                if (adapter.OperationalStatus != OperationalStatus.Up) continue;
                var desc = adapter.Description.ToLower();

                if (KnownCheats.VPNAdapterKeywords.Any(kw => desc.Contains(kw)))
                {
                    results.Add(new NetworkEntry
                    {
                        Type = "VPN Adapter",
                        Detail = $"{adapter.Name} - {adapter.Description}",
                        IsSuspicious = true,
                        Reason = "VPN/Tunnel adapter detected"
                    });
                }
            }

            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    if (ProcessScanner.IsVpnProcess(proc.ProcessName))
                    {
                        results.Add(new NetworkEntry
                        {
                            Type = "VPN Process",
                            Detail = $"{proc.ProcessName}.exe (PID: {proc.Id})",
                            IsSuspicious = true,
                            Reason = "VPN client process is running"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        return results;
    }

    private List<NetworkEntry> ScanDNSCache()
    {
        var results = new List<NetworkEntry>();
        try
        {
            var psi = new ProcessStartInfo("ipconfig", "/displaydns")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return results;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            string[] suspiciousDns =
            {
                "unknowncheats", "ugbase", "keyauth", "eauth",
                "crazycapy", "cheatermad", "napse.ac", "anticheat.ac",
                "detect.ac", "siles.ac", "abbys", "mpgh", "aimjunkies",
                "cracked.io", "nulled.to", "leak.sx", "hackforums"
            };

            foreach (var domain in suspiciousDns)
            {
                if (output.Contains(domain, StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new NetworkEntry
                    {
                        Type = "DNS Cache",
                        Detail = $"Cached DNS entry found: {domain}",
                        IsSuspicious = true,
                        Reason = "Suspicious domain in DNS cache"
                    });
                }
            }
        }
        catch { }
        return results;
    }
}
