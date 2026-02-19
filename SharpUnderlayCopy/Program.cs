using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

using System.Security.Cryptography;



namespace UnderlayCopy
{

    public static class RC4
    {
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var S = new byte[256];
            for (int i = 0; i < 256; i++) S[i] = (byte)i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % key.Length]) & 0xFF;
                (S[i], S[j]) = (S[j], S[i]);
            }

            var result = new byte[data.Length];
            int iidx = 0, jidx = 0;
            for (int k = 0; k < data.Length; k++)
            {
                iidx = (iidx + 1) & 0xFF;
                jidx = (jidx + S[iidx]) & 0xFF;
                (S[iidx], S[jidx]) = (S[jidx], S[iidx]);
                var rnd = S[(S[iidx] + S[jidx]) & 0xFF];
                result[k] = (byte)(data[k] ^ rnd);
            }
            return result;
        }
    }

    public static class AESHelper
    {
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
    public enum EncryptionType { None, RC4, AES256 }

    public static class NtfsNative
    {
        public const uint FILE_READ_ATTRIBUTES = 0x80;
        public const uint GENERIC_READ = 0x80000000;

        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;

        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

        public const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
        public const int ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME { public uint dwLowDateTime, dwHighDateTime; }

        [StructLayout(LayoutKind.Sequential)]
        public struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public FILETIME CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh, FileSizeLow;
            public uint NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            IntPtr hFile,
            out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTING_VCN_INPUT_BUFFER
        {
            public long StartingVcn;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RETRIEVAL_POINTERS_BUFFER_HEADER
        {
            public uint ExtentCount;
            public long StartingVcn;

        }
    }

    class NtfsBootInfo
    {
        public ushort BytesPerSector;
        public byte SectorsPerCluster;
        public long MftCluster;
        public long ClusterSize => BytesPerSector * SectorsPerCluster;
    }

    internal sealed class FileExtent
    {
        public long VcnStart;
        public long VcnNext;
        public long Lcn;
        public long Clusters => VcnNext - VcnStart;
        public bool IsSparse => Lcn < 0;

        public override string ToString()
            => $"VCN: 0x{VcnStart:X}  NextVCN: 0x{VcnNext:X}  Clusters: 0x{Clusters:X}  LCN: 0x{Lcn:X}";
    }

    internal sealed class DataRun
    {
        public long Lcn;
        public long Clusters;
    }

    internal sealed class ParsedData
    {
        public bool IsResident;
        public long FileSize;
        public byte[] ResidentBytes;
        public List<DataRun> Runs;
        
        class Program
        {
            private const int MFT_RECORD_SIZE = 1024;
            enum EncryptionType { None, RC4, AES256 }
            static void Main(string[] args)
            {
                // Usage: SharpUnderlayCopy.exe MFT|Metadata <source> <dest>
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: SharpUnderlayCopy.exe MFT|Metadata <source> <dest> <EncryptionType> <key> ");
                    return;
                }

                string mode = args[0];
                string sourceFile = args[1];
                string destinationFile = args[2];
                EncryptionType encType = EncryptionType.None;
                string encKey = "";
                if (args.Length > 3 )
                {
                    Enum.TryParse(args[3], true, out encType);

                }
                if (args.Length > 4) {
                    encKey = args[4];
                }
                else
                {
                    encKey = "alexlee820";
                }
                string volume = @"\\.\C:";
                string volumeRoot = @"C:\";

                if (!IsAdministrator())
                {
                    Console.Error.WriteLine("Must run as Administrator.");
                    return;
                }

                string outDir = Path.GetDirectoryName(destinationFile);
                if (!string.IsNullOrEmpty(outDir) && !Directory.Exists(outDir))
                    Directory.CreateDirectory(outDir);

                NtfsBootInfo ntfs = GetNtfsBoot(volume);
                long clusterSize = ntfs.ClusterSize;

                FileInfo fileInfo = new FileInfo(sourceFile);
                long sourceFileSize = fileInfo.Length;

                Console.WriteLine($"Source File: {sourceFile}");
                Console.WriteLine($"Size: {sourceFileSize} bytes");
                Console.WriteLine($"Cluster Size: {clusterSize} bytes");

                if (mode.Equals("Metadata", StringComparison.OrdinalIgnoreCase))
                {
                    var extents = GetFileExtentsNative(sourceFile);
                    Console.WriteLine($"Found {extents.Count} extent(s).");
                    foreach (var e in extents)
                        Console.WriteLine($"LCN={e.Lcn} LengthClusters={e.Clusters} Sparse={e.IsSparse}");

                    CopyFileByExtents(volume, extents, clusterSize, sourceFileSize, destinationFile,encType,encKey);
                    Console.WriteLine($"File copied successfully to {destinationFile}");
                }
                else if (mode.Equals("MFT", StringComparison.OrdinalIgnoreCase))
                {
                    int mftRecordNum = (int)GetNtfsFileInfo(sourceFile)["MftRecordNumber"];
                    Console.WriteLine($"MFT Record Number: {mftRecordNum}");

                    byte[] record = ReadMftRecordRobust(volume, volumeRoot, ntfs, mftRecordNum);

                    ParsedData data = ParseDataAttribute(record);

                    if (data.IsResident)
                    {
                        byte[] output = data.ResidentBytes;
                        if (encType == EncryptionType.RC4)
                            output = RC4.Encrypt(output, System.Text.Encoding.UTF8.GetBytes(encKey));
                        else if (encType == EncryptionType.AES256)
                        {
                            byte[] keyBytes = new byte[32];
                            byte[] srcKey = System.Text.Encoding.UTF8.GetBytes(encKey);
                            Array.Copy(srcKey, 0, keyBytes, 0, Math.Min(srcKey.Length, keyBytes.Length));

                            byte[] ivBytes = new byte[16]; 
                            output = AESHelper.Encrypt(output, keyBytes, ivBytes);
                        }
                        File.WriteAllBytes(destinationFile, output);
                    }
                    else
                    {
                        Console.WriteLine($"Non-resident $DATA: {data.FileSize} bytes, runs={data.Runs.Count}");
                        CopyByDataRuns(volume, data.Runs, ntfs.ClusterSize, data.FileSize, destinationFile, encType, encKey);
                    }

                    Console.WriteLine($"File copied successfully to {destinationFile}");
                }
                else
                {
                    Console.WriteLine("Invalid mode. Must be MFT or Metadata.");
                }
            }

            static bool IsAdministrator()
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }

            static NtfsBootInfo GetNtfsBoot(string volume)
            {
                IntPtr hVolume = NtfsNative.CreateFileW(
                    volume,
                    0x80000000,
                    NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    NtfsNative.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hVolume == IntPtr.Zero || hVolume == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for volume");

                using (var safeHandle = new SafeFileHandle(hVolume, ownsHandle: true))
                using (var fs = new FileStream(safeHandle, FileAccess.Read))
                {
                    byte[] buffer = new byte[512];
                    int r = fs.Read(buffer, 0, 512);
                    if (r != 512) throw new IOException("Failed to read NTFS boot sector (512 bytes).");

                    ushort bytesPerSector = BitConverter.ToUInt16(buffer, 11);
                    byte sectorsPerCluster = buffer[13];
                    long mftCluster = BitConverter.ToInt64(buffer, 48);

                    return new NtfsBootInfo
                    {
                        BytesPerSector = bytesPerSector,
                        SectorsPerCluster = sectorsPerCluster,
                        MftCluster = mftCluster
                    };
                }
            }

            static Dictionary<string, object> GetNtfsFileInfo(string path)
            {
                string norm = path.StartsWith(@"\\?\") ? path : @"\\?\" + path;
                uint access = NtfsNative.FILE_READ_ATTRIBUTES;
                uint share = NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE;
                uint disp = NtfsNative.OPEN_EXISTING;
                uint flags = NtfsNative.FILE_FLAG_BACKUP_SEMANTICS;

                IntPtr hFile = NtfsNative.CreateFileW(norm, access, share, IntPtr.Zero, disp, flags, IntPtr.Zero);
                if (hFile == IntPtr.Zero || hFile.ToInt64() == -1)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateFileW failed: {path}");

                try
                {
                    if (!NtfsNative.GetFileInformationByHandle(hFile, out var info))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), $"GetFileInformationByHandle failed: {path}");

                    ulong frn = (((ulong)info.FileIndexHigh) << 32) | info.FileIndexLow;
                    ulong mftRecord = frn & 0x0000FFFFFFFFFFFF;
                    ulong sequenceNum = (frn >> 48) & 0xFFFF;
                    ulong size = (((ulong)info.FileSizeHigh) << 32) | info.FileSizeLow;

                    return new Dictionary<string, object>
                {
                    {"VolumeSerialNumber", $"0x{info.VolumeSerialNumber:X8}"},
                    {"FileId_FRN_64", frn},
                    {"MftRecordNumber", (int)mftRecord},
                    {"SequenceNumber", sequenceNum},
                    {"IsDirectory", ((info.FileAttributes & (uint)FileAttributes.Directory) != 0)},
                    {"Links", info.NumberOfLinks},
                    {"Size", size}
                };
                }
                finally
                {
                    NtfsNative.CloseHandle(hFile);
                }
            }

            public static List<FileExtent> GetFileExtentsNative(string path)
            {
                string p = path.StartsWith(@"\\?\") ? path : @"\\?\" + path;
                uint share = NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE;

                IntPtr hFile = NtfsNative.CreateFileW(
                    p,
                    NtfsNative.FILE_READ_ATTRIBUTES,
                    share,
                    IntPtr.Zero,
                    NtfsNative.OPEN_EXISTING,
                    NtfsNative.FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hFile == IntPtr.Zero || hFile.ToInt64() == -1)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateFileW failed: {path}");


                try
                {
                    var results = new List<FileExtent>();
                    long nextStartingVcn = 0;
                    const int OUT_SIZE = 1024 * 1024;

                    IntPtr outBuf = Marshal.AllocHGlobal(OUT_SIZE);
                    IntPtr inBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NtfsNative.STARTING_VCN_INPUT_BUFFER)));

                    try
                    {
                        while (true)
                        {
                            var inStruct = new NtfsNative.STARTING_VCN_INPUT_BUFFER { StartingVcn = nextStartingVcn };
                            Marshal.StructureToPtr(inStruct, inBuf, false);

                            bool ok = NtfsNative.DeviceIoControl(
                                hFile,
                                NtfsNative.FSCTL_GET_RETRIEVAL_POINTERS,
                                inBuf,
                                (uint)Marshal.SizeOf(typeof(NtfsNative.STARTING_VCN_INPUT_BUFFER)),
                                outBuf,
                                OUT_SIZE,
                                out uint bytesReturned,
                                IntPtr.Zero);

                            int err = ok ? 0 : Marshal.GetLastWin32Error();
                            if (!ok && err != NtfsNative.ERROR_MORE_DATA)
                                throw new Win32Exception(err, "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed.");

                            if (bytesReturned < (uint)Marshal.SizeOf(typeof(NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER)))
                                throw new Exception("FSCTL_GET_RETRIEVAL_POINTERS returned too little data.");

                            var hdr = (NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER)Marshal.PtrToStructure(
                                outBuf, typeof(NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER));

                            int headerSize = Marshal.SizeOf(typeof(NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER));
                            long curVcn = hdr.StartingVcn;

                            for (int i = 0; i < hdr.ExtentCount; i++)
                            {
                                int off = headerSize + (i * 16);
                                long nextVcn = Marshal.ReadInt64(outBuf, off);
                                long lcn = Marshal.ReadInt64(outBuf, off + 8);

                                if (nextVcn > curVcn)
                                {
                                    results.Add(new FileExtent
                                    {
                                        VcnStart = curVcn,
                                        VcnNext = nextVcn,
                                        Lcn = lcn
                                    });
                                }

                                curVcn = nextVcn;
                                nextStartingVcn = nextVcn;
                            }

                            if (ok) break;
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(outBuf);
                        Marshal.FreeHGlobal(inBuf);
                    }

                    if (results.Count == 0)
                        throw new Exception("No extents returned (file may be resident in MFT / very small / special).");

                    return results;
                }
                finally
                {
                    NtfsNative.CloseHandle(hFile);
                }
            }

            static void CopyFileByExtents(string volume, List<FileExtent> extents, long clusterSize, long totalFileSize, string destinationFile, EncryptionType encType, string key ,int chunkSize = 4 * 1024 * 1024)
            {
                IntPtr hVolume = NtfsNative.CreateFileW(
                    volume,
                    0x80000000,
                    NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    NtfsNative.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hVolume == IntPtr.Zero || hVolume == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for volume");

                using (var safeHandle = new SafeFileHandle(hVolume, ownsHandle: true))
                using (var deviceFs = new FileStream(safeHandle, FileAccess.Read))
                using (var mem = new MemoryStream())
                {
                    long bytesRemaining = totalFileSize;
                    byte[] buffer = new byte[chunkSize];

                    foreach (var ext in extents)
                    {
                        if (bytesRemaining <= 0) break;

                        long clusters = ext.Clusters;
                        if (clusters <= 0) continue;

                        long extentBytes = clusters * clusterSize;
                        long toCopy = Math.Min(extentBytes, bytesRemaining);
                        if (toCopy <= 0) break;

                        if (ext.IsSparse)
                        {
                            mem.Write(new byte[toCopy], 0, (int)toCopy);
                            bytesRemaining -= toCopy;
                            continue;
                        }

                        long startOffset = checked(ext.Lcn * clusterSize);
                        deviceFs.Seek(startOffset, SeekOrigin.Begin);

                        long copied = 0;
                        while (copied < toCopy)
                        {
                            int readSize = (int)Math.Min(buffer.Length, toCopy - copied);
                            int read = 0;
                            while (read < readSize)
                            {
                                int r = deviceFs.Read(buffer, read, readSize - read);
                                if (r <= 0) throw new Exception("Unexpected end of device read");
                                read += r;
                            }
                            mem.Write(buffer, 0, read);
                            copied += read;
                        }

                        bytesRemaining -= toCopy;
                    }

                    byte[] output = mem.ToArray();
                    if (encType == EncryptionType.RC4)
                        output = RC4.Encrypt(output, System.Text.Encoding.UTF8.GetBytes(key));
                    else if (encType == EncryptionType.AES256)
                    {
                        byte[] keyBytes = new byte[32];
                        byte[] srcKey = System.Text.Encoding.UTF8.GetBytes(key);
                        Array.Copy(srcKey, 0, keyBytes, 0, Math.Min(srcKey.Length, keyBytes.Length));

                        byte[] ivBytes = new byte[16]; 
                        output = AESHelper.Encrypt(output, keyBytes, ivBytes);
                    }

                    File.WriteAllBytes(destinationFile, output);
                }
            }

            static void WriteZeros(Stream outFs, byte[] buffer, long bytes)
            {
                Array.Clear(buffer, 0, buffer.Length);
                long written = 0;
                while (written < bytes)
                {
                    int n = (int)Math.Min(buffer.Length, bytes - written);
                    outFs.Write(buffer, 0, n);
                    written += n;
                }
            }


            static byte[] ReadMftRecordRobust(string volumeDevice, string volumeRoot, NtfsBootInfo ntfs, int recordNumber)
            {
                string mftPath = Path.Combine(volumeRoot, "$MFT");
                var mftRuns = GetFileExtentsNative(mftPath);

                IntPtr hVol = NtfsNative.CreateFileW(
                    volumeDevice,
                    0x80000000,
                    NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    NtfsNative.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hVol == IntPtr.Zero || hVol == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for volume");

                var sh = new SafeFileHandle(hVol, ownsHandle: true);
                var volFs = new FileStream(sh, FileAccess.Read);

                long recordOffsetInMft = checked((long)recordNumber * MFT_RECORD_SIZE);

                byte[] record = ReadBytesFromVolumeByFileRuns(volFs, mftRuns, ntfs.ClusterSize, recordOffsetInMft, MFT_RECORD_SIZE);

                if (record.Length < 4 ||
                    record[0] != (byte)'F' || record[1] != (byte)'I' || record[2] != (byte)'L' || record[3] != (byte)'E')
                    throw new InvalidDataException("Not a valid FILE record signature (wrong record or cannot read).");

                ApplyUsaFixup(record, sectorSize: 512);

                return record;
            }

            static byte[] ReadBytesFromVolumeByFileRuns(
                FileStream volumeFs,
                List<FileExtent> runs,
                long clusterSize,
                long fileOffset,
                int length)
            {
                byte[] result = new byte[length];
                int written = 0;
                long curOff = fileOffset;

                while (written < length)
                {
                    FileExtent ext = null;
                    for (int i = 0; i < runs.Count; i++)
                    {
                        var e = runs[i];
                        long extStart = checked(e.VcnStart * clusterSize);
                        long extEnd = checked(e.VcnNext * clusterSize);
                        if (curOff >= extStart && curOff < extEnd)
                        {
                            ext = e;
                            break;
                        }
                    }

                    if (ext == null)
                        throw new InvalidDataException("Offset not covered by file runs (likely corrupt runs or bad offset).");

                    if (ext.IsSparse)
                        throw new InvalidDataException("Encountered sparse extent in $MFT mapping (unexpected).");

                    long extStartBytes = checked(ext.VcnStart * clusterSize);
                    long withinExt = curOff - extStartBytes;

                    long extEndBytes = checked(ext.VcnNext * clusterSize);
                    int canRead = (int)Math.Min(length - written, extEndBytes - curOff);

                    long diskOffset = checked(ext.Lcn * clusterSize + withinExt);
                    volumeFs.Seek(diskOffset, SeekOrigin.Begin);

                    int got = 0;
                    while (got < canRead)
                    {
                        int n = volumeFs.Read(result, written + got, canRead - got);
                        if (n <= 0) throw new IOException("Unexpected end of volume read.");
                        got += n;
                    }

                    written += canRead;
                    curOff += canRead;
                }

                return result;
            }

            static void ApplyUsaFixup(byte[] record, int sectorSize)
            {

                ushort usaOff = U16(record, 0x04);
                ushort usaCnt = U16(record, 0x06);

                if (usaOff == 0 || usaCnt < 2) return;

                int sectors = usaCnt - 1;
                if (usaOff + 2 + sectors * 2 > record.Length)
                    throw new InvalidDataException("USA array out of bounds.");

                ushort usn = U16(record, usaOff);

                for (int i = 0; i < sectors; i++)
                {
                    int fixupEntryOff = usaOff + 2 + (i * 2);
                    ushort repl = U16(record, fixupEntryOff);

                    int sectorLastWordOff = ((i + 1) * sectorSize) - 2;
                    if (sectorLastWordOff + 2 > record.Length)
                        throw new InvalidDataException("Sector boundary out of bounds for fixup.");

                    ushort cur = U16(record, sectorLastWordOff);
                    if (cur != usn)
                        throw new InvalidDataException("MFT fixup USN mismatch (record may be corrupt / wrong sector size).");

                    record[sectorLastWordOff] = (byte)(repl & 0xFF);
                    record[sectorLastWordOff + 1] = (byte)((repl >> 8) & 0xFF);
                }
            }

            static ParsedData ParseDataAttribute(byte[] record)
            {
                ushort attrOff = U16(record, 0x14);
                int pos = attrOff;

                while (pos + 8 <= record.Length)
                {
                    int type = (int)U32(record, pos);
                    if (type == unchecked((int)0xFFFFFFFF)) break;

                    int len = (int)U32(record, pos + 4);
                    if (len <= 0 || pos + len > record.Length)
                        throw new InvalidDataException("Invalid attribute length in MFT record.");

                    byte nonResident = record[pos + 8];

                    if (type == 0x80)
                    {
                        if (nonResident == 0)
                        {
                            int valueLen = (int)U32(record, pos + 16);
                            ushort valueOff = U16(record, pos + 20);

                            if (valueOff + valueLen > record.Length)
                                throw new InvalidDataException("Resident data out of bounds.");

                            var bytes = new byte[valueLen];
                            Buffer.BlockCopy(record, valueOff, bytes, 0, valueLen);

                            return new ParsedData
                            {
                                IsResident = true,
                                FileSize = valueLen,
                                ResidentBytes = bytes,
                                Runs = null
                            };
                        }
                        else
                        {
                            long realSize = I64(record, pos + 48);
                            ushort runOff = U16(record, pos + 32);

                            int runLen = len - runOff;
                            if (runLen <= 0) throw new InvalidDataException("Invalid data run length.");

                            byte[] runBytes = new byte[runLen];
                            Buffer.BlockCopy(record, pos + runOff, runBytes, 0, runLen);

                            var runs = ParseDataRuns(runBytes);

                            return new ParsedData
                            {
                                IsResident = false,
                                FileSize = realSize,
                                ResidentBytes = null,
                                Runs = runs
                            };
                        }
                    }

                    pos += len;
                }

                throw new InvalidDataException("No $DATA attribute found in MFT record.");
            }

            static List<DataRun> ParseDataRuns(byte[] runBytes)
            {
                var runs = new List<DataRun>();
                int pos = 0;
                long curLcn = 0;

                while (pos < runBytes.Length)
                {
                    byte header = runBytes[pos++];
                    if (header == 0x00) break;

                    int lenSize = header & 0x0F;
                    int offSize = (header >> 4) & 0x0F;

                    long len = 0;
                    for (int i = 0; i < lenSize; i++)
                        len |= ((long)runBytes[pos++]) << (8 * i);

                    long off = 0;
                    if (offSize > 0)
                    {
                        long tmp = 0;
                        for (int i = 0; i < offSize; i++)
                            tmp |= ((long)runBytes[pos++]) << (8 * i);
                        long signBit = 1L << (offSize * 8 - 1);
                        if ((tmp & signBit) != 0)
                            tmp -= 1L << (offSize * 8);

                        off = tmp;
                    }

                    if (offSize == 0)
                    {
                        runs.Add(new DataRun { Lcn = 0, Clusters = len });
                    }
                    else
                    {
                        curLcn += off;
                        runs.Add(new DataRun { Lcn = curLcn, Clusters = len });
                    }
                }

                return runs;
            }

            static void CopyByDataRuns(string volumeDevice, List<DataRun> runs, long clusterSize, long totalSize, string destinationFile, EncryptionType encType,  string key, int chunkSize = 4 * 1024 * 1024)
            {
                IntPtr hVol = NtfsNative.CreateFileW(
                    volumeDevice,
                    0x80000000,
                    NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE | NtfsNative.FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    NtfsNative.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hVol == IntPtr.Zero || hVol == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for volume");

                var sh = new SafeFileHandle(hVol, ownsHandle: true);
                var volFs = new FileStream(sh, FileAccess.Read);
                var mem = new MemoryStream();

                byte[] buffer = new byte[chunkSize];
                long written = 0;

                foreach (var r in runs)
                {
                    if (written >= totalSize) break;

                    long runBytes = checked(r.Clusters * clusterSize);
                    long toCopy = Math.Min(runBytes, totalSize - written);
                    if (toCopy <= 0) break;

                    if (r.Lcn == 0)
                    {
                        byte[] zeros = new byte[(int)toCopy];
                        mem.Write(zeros, 0, (int)toCopy);
                        written += toCopy;
                        continue;
                    }

                    long diskOffset = checked(r.Lcn * clusterSize);
                    volFs.Seek(diskOffset, SeekOrigin.Begin);

                    long copied = 0;
                    while (copied < toCopy)
                    {
                        int want = (int)Math.Min(buffer.Length, toCopy - copied);

                        int read = 0;
                        while (read < want)
                        {
                            int n = volFs.Read(buffer, read, want - read);
                            if (n <= 0) throw new IOException("Unexpected end of volume read.");
                            read += n;
                        }

                        mem.Write(buffer, 0, read);
                        copied += read;
                    }

                    written += toCopy;
                }

                byte[] output = mem.ToArray();
                if (encType == EncryptionType.RC4)
                    output = RC4.Encrypt(output, System.Text.Encoding.UTF8.GetBytes(key));
                else if (encType == EncryptionType.AES256)
                {
                    byte[] keyBytes = new byte[32];
                    byte[] srcKey = System.Text.Encoding.UTF8.GetBytes(key);
                    Array.Copy(srcKey, 0, keyBytes, 0, Math.Min(srcKey.Length, keyBytes.Length));

                    byte[] ivBytes = new byte[16];

                    output = AESHelper.Encrypt(output, keyBytes, ivBytes);
                }
                File.WriteAllBytes(destinationFile, output);

            }

            static ushort U16(byte[] b, int o) => BitConverter.ToUInt16(b, o);
            static uint U32(byte[] b, int o) => BitConverter.ToUInt32(b, o);
            static long I64(byte[] b, int o) => BitConverter.ToInt64(b, o);
        }
    }
}
