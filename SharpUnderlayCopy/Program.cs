using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace UnderlayCopy
{
    public static class NtfsNative
    {
        public const uint FILE_READ_ATTRIBUTES = 0x80;
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
        public static extern bool GetFileInformationByHandle(IntPtr hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

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
            // Followed by Extents[ExtentCount], each 16 bytes:
            //   long NextVcn;
            //   long Lcn;
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
        public override string ToString()
            => $"VCN: 0x{VcnStart:X}  NextVCN: 0x{VcnNext:X}  Clusters: 0x{Clusters:X}  LCN: 0x{Lcn:X}";
    }


    class Program
    {
        static void Main(string[] args)
        {
            // Usage: SharpUnderlayCopy.exe MFT|Metadata sourceFile destinationFile
            if (args.Length != 3)
            {
                Console.WriteLine("Usage: SharpUnderlayCopy.exe MFT|Metadata <source> <dest>");
                return;
            }

            string mode = args[0];
            string sourceFile = args[1];
            string destinationFile = args[2];
            string volume = @"\\.\C:";

            // Check for Administrator privileges
            if (!IsAdministrator())
            {
                Console.Error.WriteLine("Must run as Administrator.");
                return;
            }

            // Ensure output directory exists
            string outDir = Path.GetDirectoryName(destinationFile);
            if (!string.IsNullOrEmpty(outDir) && !Directory.Exists(outDir))
                Directory.CreateDirectory(outDir);

            // Parse NTFS boot sector
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
                Console.WriteLine($"Found {extents.Count} extents.");
                foreach (var e in extents)
                    Console.WriteLine($"LCN={e.Lcn} LengthClusters={e.Clusters}");
                CopyFileByExtents(volume, extents, clusterSize, sourceFileSize, destinationFile);
            }
            else if (mode.Equals("MFT", StringComparison.OrdinalIgnoreCase))
            {
                int mftRecordNum = (int)GetNtfsFileInfo(sourceFile)["MftRecordNumber"];
                using (var deviceFs = new FileStream(volume, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] record = ReadMftRecord(deviceFs, ntfs, mftRecordNum);

                }
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
                0x80000000, // GENERIC_READ
                NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE,
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
                fs.Read(buffer, 0, 512);

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
                NtfsNative.BY_HANDLE_FILE_INFORMATION info;
                if (!NtfsNative.GetFileInformationByHandle(hFile, out info))
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

                        var hdr = (NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER)Marshal.PtrToStructure(outBuf, typeof(NtfsNative.RETRIEVAL_POINTERS_BUFFER_HEADER));
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
        static void CopyFileByExtents(string volume, List<FileExtent> extents, long clusterSize, long totalFileSize, string destinationFile, int chunkSize = 4 * 1024 * 1024)
        {
            IntPtr hVolume = NtfsNative.CreateFileW(
                volume,
                0x80000000, // GENERIC_READ
                NtfsNative.FILE_SHARE_READ | NtfsNative.FILE_SHARE_WRITE,
                IntPtr.Zero,
                NtfsNative.OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (hVolume == IntPtr.Zero || hVolume == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW failed for volume");

            using (var safeHandle = new SafeFileHandle(hVolume, ownsHandle: true))
            using (var deviceFs = new FileStream(safeHandle, FileAccess.Read))
            using (var outFs = new FileStream(destinationFile, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                long bytesRemaining = totalFileSize;
                foreach (var ext in extents)
                {
                    long lcn = ext.Lcn;
                    long clusters = ext.Clusters;
                    long extentBytes = clusters * clusterSize;
                    long toCopy = Math.Min(extentBytes, bytesRemaining);
                    if (toCopy <= 0) break;

                    long startOffset = lcn * clusterSize;
                    deviceFs.Seek(startOffset, SeekOrigin.Begin);

                    long copied = 0;
                    byte[] buffer = new byte[chunkSize];
                    while (copied < toCopy)
                    {
                        int readSize = (int)Math.Min(chunkSize, toCopy - copied);
                        int read = 0;
                        while (read < readSize)
                        {
                            int r = deviceFs.Read(buffer, read, readSize - read);
                            if (r <= 0) throw new Exception("Unexpected end of device read");
                            read += r;
                        }
                        outFs.Write(buffer, 0, read);
                        copied += read;
                    }
                    bytesRemaining -= copied;
                    if (bytesRemaining <= 0) break;
                }
            }
        }

        static byte[] ReadMftRecord(FileStream fs, NtfsBootInfo ntfs, int recNum)
        {
            int MftRecordSize = 1024;
            long mftOffset = ntfs.MftCluster * ntfs.ClusterSize;
            long recOffset = mftOffset + recNum * MftRecordSize;
            fs.Seek(recOffset, SeekOrigin.Begin);
            byte[] record = new byte[MftRecordSize];
            fs.Read(record, 0, MftRecordSize);
            return record;
        }

    }
}