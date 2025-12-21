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

### ❌ MFT Mode (Not Yet Supported)

The original PowerShell version of UnderlayCopy supports **MFT mode**, which:
- Parses `$MFT` records directly
- Extracts **DATA attribute runlists**
- Reconstructs file contents entirely from raw NTFS structures

⚠️ **In the current C# implementation, MFT mode is NOT yet supported.**

### Prerequisites
- Administrator privileges

 ### Example
```
SharpUnderlayCopy Metadata C:\Windows\System32\config\SAM C:\Windows\Temp\sam.dmp
```
### Reference 
https://github.com/kfallahi/UnderlayCopy/blob/main/README.md
