# SharpUnderlayCopy (.NET / C#)

**SharpUnderlayCopy** is a **.NET (C#) reimplementation** of the original PowerShell *UnderlayCopy* utility, designed for **low-level NTFS acquisition** in scenarios where standard file I/O and **VSS** are unavailable or undesirable.

This version is intended to support **.NET loaders (e.g. NetLoader / in-memory execution)** and focuses on **raw NTFS metadata–driven acquisition** for research, red-team, and DFIR use cases.

---
## 🆕 New: Optional Evasion via RC4/AES Encryption

**SharpUnderlayCopy now includes optional encryption for on-disk and in-memory file reconstruction buffers using RC4 and AES algorithms.**  
This feature is designed to help **evade EDR (Endpoint Detection and Response) solutions** that may inspect or correlate cleartext artifacts during file acquisition. 

- **Encryption options**: RC4 or AES, selectable via function parameters or CLI switch.
- **When enabled**, file contents are encrypted during acquisition and written in an encrypted form.
- **Decryption utility** or code sample provided (see [Decrypting Acquisitions](#decrypting-acquisitions)).
- Intended for offensive research and situations requiring additional OPSEC/anti-EDR considerations.

> ⚠️ **Note:** Usage of encryption does not guarantee evasion. Use responsibly within legal and ethical boundaries.


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
SharpUnderlayCopy MFT C:\Windows\System32\config\system C:\Windows\Temp\system.dmp
SharpUnderlayCopy Metadata C:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dmp
```
## Encryption Usage Example

To acquire and encrypt a file using RC4 or AES256:

```
SharpUnderlayCopy.exe MFT C:\Windows\System32\config\sam sam RC4 key
SharpUnderlayCopy.exe Metadata C:\Windows\System32\config\System system AES256 key
SharpUnderlayCopy.exe Metadata C:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dmp AES256 key
```

- The **key** parameter is *optional*. If omitted, a default key is used.
- Supported encryption algorithms: **RC4** and **AES256**.
- Output file will be encrypted with the selected algorithm.

**Example (with default key):**
```
SharpUnderlayCopy.exe MFT C:\Windows\System32\config\System system RC4
```

### Reference 
https://github.com/kfallahi/UnderlayCopy/blob/main/README.md

## Acknowledgments

Special thanks to [bott0n](https://github.com/bott0n) for highlighting the importance of encryption during real-world use and for your valuable feedback and suggestions!
