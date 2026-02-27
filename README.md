# SharpUnderlayCopy (.NET / C#)

**SharpUnderlayCopy** is a **.NET (C#) reimplementation** of the original PowerShell *UnderlayCopy* utility, designed for **low-level NTFS acquisition** in scenarios where standard file I/O and **VSS** are unavailable or undesirable.

This version is intended to support **.NET loaders (e.g. NetLoader / in-memory execution)** and focuses on **raw NTFS metadata–driven acquisition** for research, red-team, and DFIR use cases.

---

## 🔧 Improvements over UnderlayCopy

SharpUnderlayCopy introduces several key improvements over the original PowerShell-based UnderlayCopy:

### No `fsutil` Dependency — Native `DeviceIoControl` API

The original UnderlayCopy relies on spawning `fsutil` as a child process to query NTFS cluster allocation metadata (VCN → LCN mappings). This approach has notable drawbacks in offensive and DFIR contexts:

- **Process creation is detectable** — EDR/AV solutions commonly flag or log `fsutil.exe` invocations, particularly when called programmatically from non-interactive sessions.
- **Output parsing is fragile** — fsutil output is text-based and locale-dependent, making it unreliable across system configurations.
- **No direct control** — spawning a subprocess introduces unnecessary noise and limits portability for in-memory execution.

SharpUnderlayCopy eliminates this dependency entirely by calling the **Windows API `DeviceIoControl`** directly:

| Capability | UnderlayCopy (PowerShell) | SharpUnderlayCopy (.NET/C#) |
|---|---|---|
| VCN → LCN mapping | `fsutil` subprocess | `DeviceIoControl` (`FSCTL_GET_RETRIEVAL_POINTERS`) |
| Volume sector read | `fsutil` / file API | Raw handle + `ReadFile` on `\\.\C:` |
| Process noise | Spawns `fsutil.exe` | No child process, all in-process |
| EDR visibility | High (process creation) | Lower (direct API calls) |
| Locale sensitivity | Yes (text parsing) | No (binary API response) |

By issuing `FSCTL_GET_RETRIEVAL_POINTERS` and `FSCTL_GET_NTFS_VOLUME_DATA` directly via `DeviceIoControl`, all cluster mapping is performed **in-process** with no subprocess creation, no stdout parsing, and no dependency on the `fsutil` binary being present or accessible.

---

### Encryption Support — Eliminating Cleartext Artifacts

The original UnderlayCopy writes reconstructed file contents to disk in **plaintext**, which creates forensic artifacts and may trigger EDR detections based on content signatures (e.g. NTLM hash structures in SAM/SYSTEM hives, NTDS.dit patterns).

SharpUnderlayCopy addresses this with **optional in-flight encryption** of acquired data:

- **RC4** — lightweight stream cipher, applied during buffer assembly before any disk write.
- **AES256** — stronger symmetric encryption for higher OPSEC requirements.
- Encrypted output is written directly, meaning **cleartext file content never touches disk**.
- Companion decryption scripts (`RC4encrypt.py`, `AESdecrypt.py`) are provided for offline recovery.

This significantly reduces the risk of signature-based detection during file acquisition of high-value targets such as `SAM`, `SYSTEM`, `SECURITY`, and `ntds.dit`.

---

## 🆕 New: Optional Evasion via RC4/AES Encryption

**SharpUnderlayCopy now includes optional encryption for on-disk and in-memory file reconstruction buffers using RC4 and AES algorithms.**  
This feature is designed to help **evade EDR (Endpoint Detection and Response) solutions** that may inspect or correlate cleartext artifacts during file acquisition. 

- **Encryption options**: RC4 or AES, selectable via function parameters or CLI switch.
- **When enabled**, file contents are encrypted during acquisition and written in an encrypted form.
- **Decryption utility provided**: A Python script (`AESdecrypt.py` and `RC4encrypt.py`) for AES256 and RC4 decryption is included in this repository 
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

> This mode is functionally equivalent to the original PowerShell **metadata / fsutil-based** workflow, but implemented entirely via `DeviceIoControl` with no subprocess dependency.

---

### ✅ MFT Mode (Supported)

MFT mode reconstructs files by:

- Resolving the target file's **MFT record number** (e.g. via File Reference Number / FRN)
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
