using Microsoft.Win32;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class USBHistoryScanner
{
    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanUSBHistory) return results;

        try
        {
            // Check USBSTOR for connected USB storage devices
            using var usbStorKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (usbStorKey == null) return results;

            foreach (var deviceClass in usbStorKey.GetSubKeyNames())
            {
                try
                {
                    using var deviceKey = usbStorKey.OpenSubKey(deviceClass);
                    if (deviceKey == null) continue;

                    foreach (var deviceInstance in deviceKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var instKey = deviceKey.OpenSubKey(deviceInstance);
                            if (instKey == null) continue;

                            var friendlyName = instKey.GetValue("FriendlyName")?.ToString() ?? deviceInstance;

                            // Get first/last insert times
                            string timestamp = "";
                            try
                            {
                                using var propsKey = instKey.OpenSubKey("Properties");
                                if (propsKey != null)
                                {
                                    foreach (var guid in propsKey.GetSubKeyNames())
                                    {
                                        try
                                        {
                                            using var guidKey = propsKey.OpenSubKey(guid);
                                            if (guidKey == null) continue;

                                            using var tsKey = guidKey.OpenSubKey("0064");
                                            if (tsKey != null)
                                            {
                                                var tsData = tsKey.GetValue("");
                                                if (tsData is byte[] tsBytes && tsBytes.Length >= 8)
                                                {
                                                    var ft = BitConverter.ToInt64(tsBytes, 0);
                                                    if (ft > 0)
                                                        timestamp = DateTime.FromFileTime(ft).ToString("yyyy-MM-dd HH:mm:ss");
                                                }
                                            }
                                        }
                                        catch { }
                                    }
                                }
                            }
                            catch { }

                            var deviceName = friendlyName;
                            var lower = deviceName.ToLower();

                            // Flag suspicious device names that might indicate cheat tools
                            foreach (var cheat in KnownCheats.CheatProcesses)
                            {
                                if (lower.Contains(cheat.Key.Replace(".exe", "").ToLower()))
                                {
                                    results.Add(new FileEntry
                                    {
                                        Name = deviceName,
                                        Path = $@"USBSTOR\{deviceClass}\{deviceInstance}",
                                        Source = "USB History",
                                        IsSuspicious = true,
                                        Reason = $"USB device name matches cheat: {cheat.Value}",
                                        CreationTime = string.IsNullOrEmpty(timestamp) ? null : DateTime.Parse(timestamp)
                                    });
                                    break;
                                }
                            }

                            // Flag USB drives that were recently connected (within 24 hours)
                            if (!string.IsNullOrEmpty(timestamp))
                            {
                                var insertTime = DateTime.Parse(timestamp);
                                if (insertTime > DateTime.Now.AddHours(-24))
                                {
                                    // Only flag if not already flagged
                                    if (!results.Any(r => r.Name == deviceName))
                                    {
                                        results.Add(new FileEntry
                                        {
                                            Name = deviceName,
                                            Path = $@"USBSTOR\{deviceClass}\{deviceInstance}",
                                            Source = "USB History",
                                            IsSuspicious = false,
                                            Reason = $"USB device recently connected at {timestamp}",
                                            CreationTime = insertTime
                                        });
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Also check USB enum for all USB devices
            using var usbKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\USB");
            if (usbKey != null)
            {
                foreach (var vidPid in usbKey.GetSubKeyNames())
                {
                    try
                    {
                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey == null) continue;

                        foreach (var instance in vpKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var instKey = vpKey.OpenSubKey(instance);
                                if (instKey == null) continue;

                                var deviceDesc = instKey.GetValue("DeviceDesc")?.ToString() ?? "";

                                // Check for DMA/FPGA devices
                                var lower = deviceDesc.ToLower();
                                if (lower.Contains("fpga") || lower.Contains("pcileech") ||
                                    lower.Contains("dma") && lower.Contains("capturer"))
                                {
                                    results.Add(new FileEntry
                                    {
                                        Name = deviceDesc,
                                        Path = $@"USB\{vidPid}\{instance}",
                                        Source = "USB Device",
                                        IsSuspicious = true,
                                        Reason = "DMA/FPGA device detected - possible hardware cheat"
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        return results;
    }
}
