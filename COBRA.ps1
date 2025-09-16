<#
=====================================================================
 C.O.B.R.A. – Crypto‑Object Backup & Retrieval Assistant
 Version: 1.4.0
 Author : Syrnix

 PURPOSE
   • Locate cryptocurrency wallet files, browser extensions, credential
     stores, cloud‑sync folders and (optionally) the DPAPI protect folder.
   • Copy everything to a USB stick, compute SHA‑256 hashes and write a
     JSON manifest for later forensic analysis.
   • Provide a **robust, throttled progress UI** for both scanning and
     copying stages.

 REQUIREMENTS
   • PowerShell 5.1+ (built‑in on Windows 10/11)
   • Run the script **as Administrator** (needed for protected folders)

=====================================================================
#>

#region Parameters ---------------------------------------------------------

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    # Drives to scan (default C:)
    [Parameter(ParameterSetName='Interactive')]
    [string[]] $Drives = @('C'),

    # Shallow run – skips the deep recursive scan
    [switch] $Quick,

    # Show plan only, no copy
    [switch] $DryRun,

    # Preserve original folder hierarchy on the USB
    [switch] $PreserveHierarchy,

    # Include the DPAPI Protect folder (optional)
    [switch] $IncludeDPAPI,

    # Run without any prompts (good for scheduled tasks)
    [Parameter(ParameterSetName='Unattended')]
    [switch] $Unattended,

    # Show help and exit
    [switch] $Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit
}

#endregion ------------------------------------------------------------------

#region Global state --------------------------------------------------------

# Lower‑cased exclusion list (computed once)
$global:Exclusions = @(
    "$env:SystemRoot",
    "$env:ProgramFiles",
    "$env:ProgramFiles(x86)",
    "$env:ProgramData",
    "$env:Windir\WinSxS"
) | ForEach-Object { $_.ToLower() }

# Queue of absolute source paths that will be copied
$global:Queue = @()

# Manifest entries (will be serialized to JSON)
$global:Manifest = @()

# Simple stats object
$global:Stats = [pscustomobject]@{
    CopiedFiles       = 0
    TotalBytesCopied  = 0
    FailedCopies      = 0
    SkippedFiles      = 0
    SkippedBytes      = 0
}

#endregion ------------------------------------------------------------------

#region Helper functions ----------------------------------------------------

function Show-Banner {
    $banner = @"
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 

                     C.O.B.R.A. v1.4.0
            Crypto‑Object Backup & Retrieval Assistant
-------------------------------------------------------------------
"@
    Write-Host $banner -ForegroundColor Green
    Write-Host "Pre‑run checklist (verify before proceeding):" -ForegroundColor Cyan
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
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts $Message"
    Write-Host $line -ForegroundColor $Color
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
            $bytes = $hasher.ComputeHash($stream)
            return ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
        }
    } catch {
        Write-Log "Failed to hash $Path : $_" Yellow
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
            Write-Log "⚠️  Drive $raw not found – try again." Red
            continue
        }

        $free = (Get-PSDrive $raw).Free
        if ($free -lt $minFree) {
            Write-Log "⚠️  Drive $raw has less than 100 MiB free – choose another." Red
            continue
        }

        return $raw
    } while ($true)
}

function Estimate-TotalSize {
    $total = 0
    foreach ($p in $global:Queue) {
        try {
            $info = Get-Item $p -ErrorAction Stop
            if (-not $info.PSIsContainer) { $total += $info.Length }
        } catch {}
    }
    return $total
}

function Show-QueuePreview {
    param(
        [int]$MaxEntries = 100,
        [int]$TreeDepth  = 3
    )
    $preview = $global:Queue | Select-Object -First $MaxEntries
    $size = 0
    foreach ($p in $preview) {
        $fi = Get-Item $p -ErrorAction SilentlyContinue
        if ($fi -and -not $fi.PSIsContainer) { $size += $fi.Length }
    }
    $mb = [math]::Round($size/1MB,2)
    Write-Log "`nQueue preview (first $MaxEntries items, ~${mb} MiB):" Cyan
    foreach ($p in $preview) {
        $rel = $p -replace '^[A-Z]:\\',''
        $parts = $rel.Split('\')
        $display = ($parts[0..([math]::Min($TreeDepth,$parts.Count)-1)] -join '\')
        Write-Host "  $display"
    }
    if ($global:Queue.Count -gt $MaxEntries) {
        Write-Host "  … ($($global:Queue.Count-$MaxEntries) more files not shown)"
    }
}

# -------------------------------------------------------------------------
# Unified progress wrapper – works for any foreach‑style enumeration
function Invoke-With-Progress {
<#
.SYNOPSIS
    Executes a foreach loop while showing a throttled Write‑Progress bar.

.PARAMETER Items
    Collection to enumerate (array, IEnumerable, etc.).

.PARAMETER Activity
    Short description shown as the Progress “Activity”.

.PARAMETER Status
    Optional sub‑status (e.g. “Scanning files”, “Copying”).

.PARAMETER ScriptBlock
    Code to run for each element. The current element is passed as $_.

.PARAMETER UpdateEvery
    Minimum number of items processed before forcing an update
    (default = 1, i.e. update on every percent change).

.EXAMPLE
    $files = Get-ChildItem -Recurse -File .
    Invoke-With-Progress -Items $files `
        -Activity "Deep‑scan (keyword)" `
        -ScriptBlock {
            if ($_.Length -lt 50MB -and (Select-String -Path $_.FullName -Pattern $regex -Quiet)) {
                Add-To-Queue $_.FullName
            }
        }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IEnumerable] $Items,
        [Parameter(Mandatory)][string] $Activity,
        [string] $Status = '',
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [int] $UpdateEvery = 1
    )

    $total = $Items.Count
    if ($total -eq 0) {
        Write-Host "⚠️  Nothing to process for '$Activity'." -ForegroundColor Yellow
        return
    }

    $processed   = 0
    $lastPercent = -1
    $startTime   = Get-Date

    try {
        foreach ($item in $Items) {
            $processed++
            & $ScriptBlock $item

            $percent = [int](($processed / $total) * 100)

            # Update only when % changes or we hit $UpdateEvery items
            if ($percent -ne $lastPercent -or ($processed % $UpdateEvery) -eq 0) {
                $elapsed = (Get-Date) - $startTime
                $etaSec = if ($percent -gt 0) {
                    [int]($elapsed.TotalSeconds * (100 - $percent) / $percent)
                } else { 0 }

                Write-Progress -Activity $Activity `
                               -Status $Status `
                               -PercentComplete $percent `
                               -CurrentOperation ("{0}/{1}" -f $processed,$total) `
                               -SecondsRemaining $etaSec
                $lastPercent = $percent
            }
        }
    }
    finally {
        Write-Progress -Activity $Activity -Completed
        $duration = (Get-Date) - $startTime
        Write-Host ("✅  Finished '{0}' – processed {1:N0} items in {2:g}" -f $Activity,$total,$duration) `
                   -ForegroundColor Green
    }
}
# -------------------------------------------------------------------------

#endregion ------------------------------------------------------------------

#region Main execution -------------------------------------------------------

Show-Banner

# ---------- USB drive selection ----------
if ($Unattended) {
    if (-not $env:COBRA_USB_DRIVE) {
        Write-Log "🚫  Unattended mode requires env var COBRA_USB_DRIVE." Red
        exit 1
    }
    $usbDrive = $env:COBRA_USB_DRIVE.Trim().TrimEnd(':')
} else {
    $usbDrive = Prompt-For-UsbDrive
}
$usbRoot = "${usbDrive}:\"

# ---------- Destination layout ----------
$backupRoot   = Join-Path $usbRoot "COBRA_Evidence"
$timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$sessionFolder= Join-Path $backupRoot "Session_$timestamp"

if (Test-Path $sessionFolder) {
    Write-Log "⚠️  Session folder already exists – aborting to avoid overwrite." Red
    exit 1
}
New-Item -ItemType Directory -Path $sessionFolder -Force | Out-Null

# Log file (same folder as manifest)
$global:LogPath = Join-Path $sessionFolder "session.log"
Write-Log "=== C.O.B.R.A. run started ===" Green
Write-Log "Destination root: $sessionFolder"

# ---------- Phase 1 – Known wallet / browser / cloud folders ----------
Write-Log "`n[Phase 1] Queuing known locations…" Cyan

# Wallet folders
$walletFolders = @(
    "$env:APPDATA\Bitcoin",
    "$env:APPDATA\Ethereum\keystore",
    "$env:APPDATA\Electrum\wallets",
    "$env:APPDATA\Exodus",
    "$env:APPDATA\Litecoin",
    "$env:APPDATA\Armory"
)
$walletFolders | Invoke-With-Progress -Activity "Wallet folders" `
    -ScriptBlock { param($f) Add-To-Queue $f }

# Browser extensions
$browserExtFolders = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
)
$browserExtFolders | Invoke-With-Progress -Activity "Browser extensions" `
    -ScriptBlock { param($f) Add-To-Queue $f }

# Browser credential files
$browserCredFiles = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
)
$browserCredFiles | Invoke-With-Progress -Activity "Browser credential files" `
    -ScriptBlock { param($f) Add-To-Queue $f }

# Optional DPAPI protect folder
if ($IncludeDPAPI) {
    $dpapiFolder = "$env:APPDATA\Microsoft\Protect"
    $dpapiFolder | Invoke-With-Progress -Activity "DPAPI protect folder" `
        -ScriptBlock { param($f) Add-To-Queue $f }
}

# Cloud sync folders
$cloudSyncFolders = @(
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\Dropbox",
    "$env:USERPROFILE\Google Drive"
)
$cloudSyncFolders | Invoke-With-Progress -Activity "Cloud‑sync folders" `
    -ScriptBlock { param($f) Add-To-Queue $f }

# ---------- Phase 2 – Deep recursive scan (optional) ----------
if (-not $Quick) {
    Write-Log "`n[Phase 2] Performing deep recursive scan…" Cyan

    # Patterns we care about (filename‑only)
    $searchPatterns = @(
        "wallet.dat","*.wallet","*keystore*","UTC--*.json",
        "*.key","*.pem","*.seed","*.mnemonic"
    )
    # Text‑file extensions we will actually read
    $textExtensions = @("*.txt","*.md","*.log")
    # Keyword regex (case‑insensitive)
    $keywordRegex = '(mnemonic|seed|recovery|password|private\s*key|phrase)'
    # Upper bound for reading a text file (avoid huge logs)
    $maxScanSize = 50MB

    # Build a flat list of *candidate* files first – this keeps the progress bar smooth
    $candidateFiles = foreach ($drive in $Drives) {
        $root = "${drive}:\"
        if (-not (Test-Path $root)) { continue }

        # 1️⃣ Files matching known wallet‑like names
        foreach ($pat in $searchPatterns) {
            Get-ChildItem -Path $root -Filter $pat -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-Exclude $_.FullName) }
        }

        # 2️⃣ Text files that might contain keywords
        foreach ($ext in $textExtensions) {
            Get-ChildItem -Path $root -Include $ext -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { -not (Should-Exclude $_.FullName) }
        }
    }

    # Process the candidates with a progress bar
    $candidateFiles | Invoke-With-Progress -Activity "Deep‑scan (filename + keyword)" `
        -Status "Evaluating $($candidateFiles.Count) potential artefacts" `
        -ScriptBlock {
            param($item)

            # Fast‑path: filename already matches a wallet pattern
            if ($searchPatterns -contains $item.Name) {
                Add-To-Queue $item.FullName
                return
            }

            # Otherwise treat it as a possible text file and look for keywords
            if ($item.Extension -in $textExtensions -and $item.Length -lt $maxScanSize) {
                $found = Select-String -Path $item.FullName -Pattern $keywordRegex -SimpleMatch -Quiet -ErrorAction SilentlyContinue
                if ($found) { Add
