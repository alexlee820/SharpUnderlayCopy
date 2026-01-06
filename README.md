# SharpUnderlayCopy (.NET / C#)

**SharpUnderlayCopy** is a **.NET (C#) reimplementation** of the original PowerShell *UnderlayCopy* utility, designed for **low-level NTFS acquisition** in scenarios where standard file I/O and **VSS** are unavailable or undesirable.

This version is intended to support **.NET loaders (e.g. NetLoader / in-memory execution)** and focuses on **raw NTFS metadata–driven acquisition** for research, red-team, and DFIR use cases.

---

## Supported Modes

### ✅ Metadata Mode (Supported)

Metadata mode reconstructs files by:

- Querying NTFS allocation metadata (VCN → LCN mappings)
- Mapping files to their underlying disk clusters
- Reading raw sectors directly from the volume (e.g. `\\.\C:`)
- Reassembling file contents without using standard file reads

This approach enables access to **files that are locked or protected at the Win32 API level**, while still relying on filesystem metadata rather than snapshots.

> This mode is functionally equivalent to the original PowerShell **metadata / fsutil-based** workflow.

---

### ✅ MFT Mode (Supported)

MFT mode reconstructs files by:

- Resolving the target file’s **MFT record number** (e.g. via File Reference Number / FRN)
- Reading the corresponding **$MFT entry** directly from disk using raw volume access (e.g. `\\.\C:`)
- Parsing NTFS attributes inside the record (notably **$FILE_NAME** and **$DATA**)
- Extracting **data runs** from the non-resident `$DATA` attribute (LCN + cluster length ranges)
- Reading raw clusters directly from the volume based on recovered **LCN mappings**
- Reassembling file contents **without using standard Win32 file reads** and **without querying live allocation metadata**

This approach enables access to **files even when filesystem allocation queries are blocked, restricted, or unreliable**, because file layout is derived from the **on-disk NTFS Master File Table ($MFT)** rather than from runtime filesystem APIs.

> This mode is functionally equivalent to the original PowerShell **MFT parsing / data-runs–based** workflow (read MFT record → parse `$DATA` runs → raw volume copy).

> **Note:** For very small files with *resident* `$DATA`, content may be extracted directly from the MFT record without any raw disk reads.

### Prerequisites
- Administrator privileges

 ### Example
```
SharpUnderlayCopy Metadata C:\Windows\System32\config\SAM C:\Windows\Temp\sam.dmp
```
### Reference 
https://github.com/kfallahi/UnderlayCopy/blob/main/README.md
