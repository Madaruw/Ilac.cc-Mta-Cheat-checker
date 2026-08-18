using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Ilac.Shared.Helpers;
using Ilac.Shared.Models;

namespace Ilac.Shared.Scanners;

public class USNJournalScanner
{
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
    private const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    private const uint USN_REASON_FILE_DELETE = 0x00000200;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ_WRITE = 0x3;
    private const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        Microsoft.Win32.SafeHandles.SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA
    {
        public ulong UsnJournalID;
        public long FirstUsn, NextUsn, LowestValidUsn, MaxUsn;
        public long MaximumSize, AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct READ_USN_JOURNAL_DATA_V1
    {
        public ulong StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
        public ushort MinMajorVersion;
        public ushort MaxMajorVersion;
    }

    public List<FileEntry> Scan(ScanConfig config)
    {
        var results = new List<FileEntry>();
        if (!config.ScanUSNJournal || !config.ScanDeletedFiles) return results;

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType != DriveType.Fixed && drive.DriveType != DriveType.Removable) continue;
            if (!drive.IsReady) continue;
            var letter = drive.Name.TrimEnd('\\', '/');
            if (string.IsNullOrEmpty(letter)) continue;

            try { results.AddRange(ReadJournalWin32(letter)); }
            catch (Exception ex)
            {
                try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                    $"[{DateTime.Now:HH:mm:ss}] {letter}: EXCEPTION: {ex.Message}\n"); } catch { }
            }
        }

        // Filter to last 2 hours
        var cutoff = DateTime.UtcNow.AddHours(-2);
        results = results.Where(f => !f.LastModifiedTime.HasValue || f.LastModifiedTime.Value >= cutoff).ToList();

        return results;
    }

    private List<FileEntry> ReadJournalWin32(string drive)
    {
        var results = new List<FileEntry>();
        var volPath = @"\\.\" + drive;

        try
        {
        using var h = CreateFileW(volPath, GENERIC_READ, FILE_SHARE_READ_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (h.IsInvalid)
        {
            var err = Marshal.GetLastWin32Error();
            try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                $"[{DateTime.Now:HH:mm:ss}] {drive}: CreateFileW failed, error={err}\n"); } catch { }
            return results;
        }

        // Query journal info
        var jdSize = Marshal.SizeOf<USN_JOURNAL_DATA>();
        var qBuf = Marshal.AllocHGlobal(jdSize);
        USN_JOURNAL_DATA jd;
        try
        {
            if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qBuf, (uint)jdSize, out _, IntPtr.Zero))
            {
                var err = Marshal.GetLastWin32Error();
                try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                    $"[{DateTime.Now:HH:mm:ss}] {drive}: QueryJournal failed, error={err}\n"); } catch { }
                return results;
            }
            jd = Marshal.PtrToStructure<USN_JOURNAL_DATA>(qBuf);
        }
        finally { Marshal.FreeHGlobal(qBuf); }

        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
            $"[{DateTime.Now:HH:mm:ss}] {drive}: JournalID=0x{jd.UsnJournalID:X} NextUsn={jd.NextUsn}\n"); } catch { }

        // Read journal with FILE_DELETE filter
        var rd = new READ_USN_JOURNAL_DATA_V1
        {
            ReasonMask = USN_REASON_FILE_DELETE,
            UsnJournalID = jd.UsnJournalID,
            MinMajorVersion = 2,
            MaxMajorVersion = 4
        };
        var rdSize = Marshal.SizeOf<READ_USN_JOURNAL_DATA_V1>();
        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
            $"[{DateTime.Now:HH:mm:ss}] {drive}: structSize={rdSize}\n"); } catch { }

        var inBuf = Marshal.AllocHGlobal(rdSize);
        var outBuf = Marshal.AllocHGlobal(0x10000); // 64KB

        try
        {
            int batchCount = 0;
            for (;;)
            {
                Marshal.StructureToPtr(rd, inBuf, false);
                if (!DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, inBuf, (uint)rdSize,
                    outBuf, 0x10000, out var got, IntPtr.Zero))
                {
                    var err = Marshal.GetLastWin32Error();
                    try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                        $"[{DateTime.Now:HH:mm:ss}] {drive}: ReadJournal error={err} (38=EOF)\n"); } catch { }
                    if (err == 38) break; // ERROR_HANDLE_EOF
                    break;
                }

                if (got < 8) break;
                var nextUsn = (ulong)Marshal.ReadInt64(outBuf);

                int off = 8;
                int recordsInBatch = 0;

                while (off + 8 <= (int)got)
                {
                    var recLen = (uint)Marshal.ReadInt32(outBuf + off);
                    if (recLen < 8 || off + recLen > got) break;

                    var major = (ushort)Marshal.ReadInt16(outBuf + off + 4);

                    // USN_RECORD field offsets
                    int oUsn = major >= 3 ? 40 : 24;
                    int oTime = major >= 3 ? 48 : 32;
                    int oReas = major >= 3 ? 56 : 40;
                    int oFnL = major >= 3 ? 72 : 56;
                    int oFnO = major >= 3 ? 74 : 58;

                    var ts = Marshal.ReadInt64(outBuf + off + oTime);
                    var when = DateTime.FromFileTimeUtc(ts);

                    var fnLen = (ushort)Marshal.ReadInt16(outBuf + off + oFnL);
                    var fnOff = (ushort)Marshal.ReadInt16(outBuf + off + oFnO);

                    if (batchCount == 0 && recordsInBatch == 0)
                    {
                        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                            $"[{DateTime.Now:HH:mm:ss}] {drive}: firstRecord: major={major} recLen={recLen} fnLen={fnLen} fnOff={fnOff} when={when:HH:mm:ss}\n"); } catch { }
                    }

                    if (fnLen > 0 && fnOff + fnLen <= recLen)
                    {
                        var nb = new byte[fnLen];
                        Marshal.Copy(outBuf + off + fnOff, nb, 0, fnLen);
                        var fileName = Encoding.Unicode.GetString(nb).TrimEnd('\0');

                        if (!string.IsNullOrEmpty(fileName))
                        {
                            var lower = fileName.ToLower();

                            // Only show .exe, .dll, .asi, .lua files
                            // Only show suspicious/cheat-related files — NOT system/build files
                            bool show = false;
                            string reason = "Son silinen dosya (USN)";

                            if (KnownCheats.CheatProcesses.TryGetValue(lower, out var cheatReason))
                            {
                                show = true;
                                reason = $"Silinen hile: {cheatReason}";
                            }
                            else if (KnownCheats.ContainsCheatBrand(lower))
                            {
                                show = true;
                                reason = "Silinen hile markasi";
                            }
                            else if (KnownCheats.IsMtaCheat(lower))
                            {
                                show = true;
                                reason = "MTA ile ilgili silinen dosya";
                            }
                            else if (KnownCheats.CheatModules.TryGetValue(lower, out var modReason))
                            {
                                show = true;
                                reason = $"Silinen hile modulu: {modReason}";
                            }
                            else
                            {
                                // Check patterns only
                                foreach (var pattern in KnownCheats.CheatFilePatterns)
                                {
                                    var matchStr = pattern.Replace("*", "").ToLower();
                                    if (!string.IsNullOrEmpty(matchStr) && lower.Contains(matchStr))
                                    {
                                        show = true;
                                        reason = $"Silinen supheli dosya (pattern: {pattern})";
                                        break;
                                    }
                                }
                            }

                            if (show)
                                {
                                    var entry = new FileEntry
                                    {
                                        Name = fileName,
                                        Path = $"{drive}:\\...\\" + fileName,
                                        Source = "USN Journal",
                                        LastExecutionTime = when,
                                        LastModifiedTime = when,
                                        Reason = reason,
                                        IsSuspicious = true
                                    };

                                    results.Add(entry);
                                }
                            }
                        }

                    recordsInBatch++;
                    off += (int)recLen;
                }

                batchCount++;
                try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
                    $"[{DateTime.Now:HH:mm:ss}] {drive}: batch={batchCount} got={got} records={recordsInBatch} total={results.Count}\n"); } catch { }

                if (nextUsn <= rd.StartUsn) break;
                rd.StartUsn = nextUsn;

                // Safety — don't read more than 500 batches
                if (batchCount > 500) break;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(inBuf);
            Marshal.FreeHGlobal(outBuf);
        }

        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
            $"[{DateTime.Now:HH:mm:ss}] {drive}: DONE, found={results.Count}\n"); } catch { }

        return results;
    }
    catch (Exception ex)
    {
        try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "ilac_usn_debug.log"),
            $"[{DateTime.Now:HH:mm:ss}] {drive}: EXCEPTION: {ex.Message}\n"); } catch { }
        return results;
    }
    }

    public bool IsJournalCleared(ScanConfig config)
    {
        if (!config.ScanUSNJournal) return false;
        try
        {
            var volPath = @"\\.\C:";
            using var h = CreateFileW(volPath, GENERIC_READ, FILE_SHARE_READ_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid) return false;

            var jdSize = Marshal.SizeOf<USN_JOURNAL_DATA>();
            var qBuf = Marshal.AllocHGlobal(jdSize);
            try
            {
                return !DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qBuf, (uint)jdSize, out _, IntPtr.Zero);
            }
            finally { Marshal.FreeHGlobal(qBuf); }
        }
        catch { return false; }
    }
}
