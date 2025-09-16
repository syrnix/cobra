<#
=====================================================================
 C.O.B.R.A. - Crypto-Object Backup & Retrieval Assistant
 Author: Syrnix
 Version: 1.3.0
 Date:   2025-09-16
 Description:
   • Enumerates common wallet locations, browser stores, and generic
     text files for crypto‑related keywords.
   • Allows the analyst to specify which drives to scan.
   • Generates a detailed JSON manifest + SHA‑256 hashes.
   • Supports Dry‑Run, Quick, and Unattended modes.
   • USB‑ready: asks for drive letter and saves artefacts there.
Prerequisites:
   • PowerShell 5.1+ (built‑in on Windows 10/11)
   • Administrative privileges (to read protected folders)
=====================================================================
#>

#region Parameters ---------------------------------------------------------

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    # Drives to scan (default C:)
    [Parameter(ParameterSetName='Interactive')]
    [string[]] $Drives = @('C'),

    # Run a shallow collection (wallet + browser only)
    [switch] $Quick,

    # Show plan only, no copy
    [switch] $DryRun,

    # Preserve original folder hierarchy on the USB
    [switch] $PreserveHierarchy,

    # Include the DPAPI protect folder (optional, may contain sensitive blobs)
    [switch] $IncludeDPAPI,

    # Run without any prompts (useful for automation)
    [Parameter(ParameterSetName='Unattended')]
    [switch] $Unattended,

    # Show help
    [switch] $Help
)

if ($Help) {
    . "$PSScriptRoot\${MyInvocation.MyCommand.Name}" -Help
    exit
}

#endregion ------------------------------------------------------------------

#region Global Variables ----------------------------------------------------

# Pre‑lower‑cased exclusion list (computed once)
$global:Exclusions = @(
    "$env:SystemRoot",
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:ProgramData",
    "$env:Windir\WinSxS"
) | ForEach-Object { $_.ToLower() }

# Queue that will hold absolute source paths
$global:Queue = @()

# Manifest entries will be stored here
$global:Manifest = @()

#endregion ------------------------------------------------------------------

#region Helper Functions ----------------------------------------------------

function Show-Banner {
    $banner = @"
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 

                     C.O.B.R.A. v1.3.0
            Crypto‑Object Backup & Retrieval Assistant
-------------------------------------------------------------------
"@
    Write-Host $banner -ForegroundColor Green
    Write-Host "Pre‑run checklist (please verify):" -ForegroundColor Cyan
    Write-Host " • PowerShell is running **as Administrator**"
    Write-Host " • USB drive is formatted FAT32/ExFAT and has ≥100 MiB free"
    Write-Host " • Destination folder will be created under <USB>\COBRA_Evidence\Session_<timestamp>"
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$timestamp $Message"
    # Write to console
    Write-Host $line -ForegroundColor $Color
    # Append to log file (created later)
    if ($global:LogPath) {
        $line | Out-File -FilePath $global:LogPath -Append -Encoding utf8
    }
}

function Compute-Hash {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        using ($stream = [IO.File]::OpenRead($Path)) {
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $hasher.ComputeHash($stream)
            return ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
        }
    } catch {
        Write-Log "Failed to hash $Path: $_" Yellow
        return $null
    }
}

function Add-To-Queue {
    param([string]$SourcePath)
    if (-not (Test-Path $SourcePath)) { return }
    if ($global:Queue -contains $SourcePath) { return }
    $global:Queue += $SourcePath
}

function Should-Exclude {
    param([string]$Path)
    $norm = $Path.ToLower()
    foreach ($ex in $global:Exclusions) {
        if ($norm.StartsWith($ex)) { return $true }
    }
    return $false
}

function Prompt-For-UsbDrive {
    do {
        $raw = Read-Host "Enter the drive letter of your USB device (e.g., E)"
        $raw = $raw.Trim().TrimEnd(':')
        $usbRoot = "${raw}:\"
        $minFree = 100 * 1MB

        if (-not (Test-Path $usbRoot)) {
            Write-Log "Warning: Drive $raw does not exist or is not accessible. Try again." Red
            continue
        }

        $free = (Get-PSDrive $raw).Free
        if ($free -lt $minFree) {
            Write-Log "Warning: USB drive $raw has less than 100 MiB free. Choose another drive." Red
            continue
        }

        return $raw
    } while ($true)
}

function Estimate-TotalSize {
    $total = 0
    foreach ($item in $global:Queue) {
        try {
            $info = Get-Item $item -ErrorAction Stop
            if (-not $info.PSIsContainer) { $total += $info.Length }
        } catch {}
    }
    return $total
}

function Show-QueuePreview {
    param(
        [int]$MaxEntries = 100,
        [int]$TreeDepth = 3
    )
    $preview = $global:Queue | Select-Object -First $MaxEntries
    $size = 0
    foreach ($p in $preview) {
        $fi = Get-Item $p -ErrorAction SilentlyContinue
        if ($fi -and -not $fi.PSIsContainer) { $size += $fi.Length }
    }
    $mb = [math]::Round($size/1MB,2)
    Write-Log "Files queued for copy (first $MaxEntries): $($preview.Count)" Cyan
    Write-Log "Estimated total size (preview): $mb MB" Cyan
    foreach ($p in $preview) {
        $rel = $p -replace '^[A-Z]:\\',''
        $parts = $rel.Split('\')
        $display = ($parts[0..([math]::Min($TreeDepth,$parts.Count)-1)] -join '\')
        Write-Host "  $display"
    }
    if ($global:Queue.Count -gt $MaxEntries) {
        Write-Host "  ... ($($global:Queue.Count - $MaxEntries) more files not shown)"
    }
}

#endregion ------------------------------------------------------------------

#region Main Execution -----------------------------------------------------

# -------------------- Banner & Summary ------------------------------------
Show-Banner

# Determine USB drive (skip prompt in unattended mode)
if ($Unattended) {
    if (-not $env:COBRA_USB_DRIVE) {
        Write-Log "Unattended mode requires env var COBRA_USB_DRIVE to be set." Red
        exit 1
    }
    $usbDrive = $env:COBRA_USB_DRIVE.Trim().TrimEnd(':')
} else {
    $usbDrive = Prompt-For-UsbDrive
}
$usbRoot = "${usbDrive}:\"

# Prepare destination folders
$backupRoot   = Join-Path $usbRoot "COBRA_Evidence"
$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$sessionFolder= Join-Path $backupRoot "Session_$timestamp"

# Guard against accidental overwrite (should never happen because of timestamp)
if (Test-Path $sessionFolder) {
    Write-Log "Session folder already exists! Aborting to avoid data loss." Red
    exit 1
}
New-Item -ItemType Directory -Path $sessionFolder -Force | Out-Null

# Initialise log file (same folder as manifest)
$global:LogPath = Join-Path $sessionFolder "session.log"
Write-Log "=== C.O.B.R.A. run started ===" Green
Write-Log "Destination root: $sessionFolder"

# -------------------- Build collection queues ---------------------------
Write-Log "`n[1/5] Queuing known wallet folders…" Cyan
$walletFolders = @(
    "$env:APPDATA\Bitcoin",
    "$env:APPDATA\Ethereum\keystore",
    "$env:APPDATA\Electrum\wallets",
    "$env:APPDATA\Exodus",
    "$env:APPDATA\Litecoin",
    "$env:APPDATA\Armory"
)
foreach ($f in $walletFolders) { Add-To-Queue $f }

Write-Log "`n[2/5] Queuing browser extension directories…" Cyan
$browserExtensionFolders = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
)
foreach ($f in $browserExtensionFolders) { Add-To-Queue $f }

Write-Log "`n[3/5] Queuing browser credential files…" Cyan
$browserCredentialFiles = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
)
foreach ($f in $browserCredentialFiles) { Add-To-Queue $f }

# Optional DPAPI folder
if ($IncludeDPAPI) {
    Write-Log "`n[3b] Including DPAPI protect folder…" Cyan
    $dpapiFolder = "$env:APPDATA\Microsoft\Protect"
    Add-To-Queue $dpapiFolder
}

Write-Log "`n[4/5] Queuing cloud‑sync directories…" Cyan
$cloudSyncFolders = @(
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\Dropbox",
    "$env:USERPROFILE\Google Drive"
)
foreach ($f in $cloudSyncFolders) { Add-To-Queue $f }

# Deep recursive search (skipped in Quick mode)
if (-not $Quick) {
    Write-Log "`n[5/5] Performing deep recursive search…" Cyan

    $searchPatterns = @(
        "wallet.dat","*.wallet","*keystore*","UTC--*.json",
        "*.key","*.pem","*.seed","*.mnemonic"
    )
    $textExtensions = @("*.txt","*.md","*.log")   # limit to true text files
    $keywordRegex = '(mnemonic|seed|recovery|password|private\s*key|phrase)'
    $maxScanSize   = 50MB

    foreach ($drive in $Drives) {
        $root = "${drive}:\"
        if (-not (Test-Path $root)) {
            Write-Log "Drive $drive does not exist – skipping." Yellow
            continue
        }

        # 1️⃣ Known wallet‑like filenames
        foreach ($pat in $searchPatterns) {
            Get-ChildItem -Path $root -Filter $pat -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-Exclude $_.FullName) } |
                ForEach-Object { Add-To-Queue $_.FullName }
        }

        # 2️⃣ Text‑file keyword scan (stream‑based)
        foreach ($ext in $textExtensions) {
            Get-ChildItem -Path $root -Include $ext -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-Exclude $_.FullName) } |
                ForEach-Object {
                    try {
                        if ($_.Length -lt $maxScanSize) {
                            $found = Select-String -Path $_.FullName -Pattern $keywordRegex -SimpleMatch -Quiet -ErrorAction SilentlyContinue
                            if ($found) { Add-To-Queue $_.FullName }
                        }
                    } catch {
                        Write-Log "Error reading $($_.FullName): $($_.Exception.Message)" Yellow
                    }
                }
        }
    }
} else {
    Write-Log "`n[5/5] Quick mode – deep recursive scan skipped." Cyan
}

# -------------------- Preview & Confirmation ----------------------------
$totalQueued = $global:Queue.Count
Write-Log "`nQueue built – $totalQueued items identified." Cyan
Show-QueuePreview -MaxEntries 100 -TreeDepth 3

# Verify we have enough space on the USB drive
$estimatedSize = Estimate-TotalSize
$freeOnUsb    = (Get-PSDrive $usbDrive).Free
if ($estimatedSize -gt ($freeOnUsb - 100MB)) {
    $needMb = [math]::Round($estimatedSize/1MB,2)
    $freeMb = [math]::Round($freeOnUsb/1MB,2)
    Write-Log "Insufficient free space on $usbDrive. Need ≈$needMb MB, have $freeMb MB." Red
    exit 1
}
Write-Log "Estimated total payload size: $([math]::Round($estimatedSize/1MB,2)) MB" Cyan

# Confirmation (auto‑yes in unattended mode)
if ($Unattended) {
    $proceed = $true
} else {
    $answer = Read-Host "`nProceed with copying all queued artefacts? (Y/N)"
    $proceed = $answer -eq 'Y'
}
if (-not $proceed) {
    Write-Log "Copy aborted by user." Red
    exit 0
}

# Dry‑run handling
if ($DryRun) {
    Write-Log "`nDry‑Run mode active – no files will be copied." Yellow
    Write-Log "=== C.O.B.R.A. finished (dry‑run) ===" Green
    exit 0
}

# -------------------- Copy Operation -----------------------------------
Write-Log "`nStarting copy operation…" Cyan

$copied = 0
$failed = 0
$counter = 0
$totalFiles = $global:Queue.Count
$lastPct = -1

foreach ($src in $global:Queue) {
    $counter++
    $pct = [int](($counter/$totalFiles)*100)
    if ($pct -ne $lastPct) {
        Write-Progress -Activity "COBRA
