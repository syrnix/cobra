# C.O.B.R.A. – Crypto‑Object Backup & Retrieval Assistant

*C.O.B.R.A.* scans a Windows system for cryptocurrency‑related artefacts (wallet files, browser extensions, credential stores, cloud‑sync folders, and optionally the DPAPI protect folder). It copies the discovered items to a USB drive, records a SHA‑256 hash for each file, and generates a JSON manifest together with a session log.

---

## How to use

1. **Open PowerShell as Administrator** – the script needs elevated rights to read protected locations.  
2. **Save the script** (e.g., `COBRA.ps1`) to a convenient folder.  
3. **Run the script** with the desired options. Example for a full scan of the C: drive while preserving the original folder hierarchy on the USB:

   ```powershell
   .\COBRA.ps1 -Drives C -PreserveHierarchy
