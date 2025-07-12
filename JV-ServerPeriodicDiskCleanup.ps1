# Justin Verstijnen Server Periodic Disk Cleanup script
# Github page: hhttps://github.com/JustinVerstijnen/JV-ServerPeriodicDiskCleanup
# Let's start!
Write-Host "Script made by..." -ForegroundColor DarkCyan
Write-Host "     _           _   _        __     __            _   _  _                  
    | |_   _ ___| |_(_)_ __   \ \   / /__ _ __ ___| |_(_)(_)_ __   ___ _ __  
 _  | | | | / __| __| | '_ \   \ \ / / _ \ '__/ __| __| || | '_ \ / _ \ '_ \ 
| |_| | |_| \__ \ |_| | | | |   \ V /  __/ |  \__ \ |_| || | | | |  __/ | | |
 \___/ \__,_|___/\__|_|_| |_|    \_/ \___|_|  |___/\__|_|/ |_| |_|\___|_| |_|
                                                       |__/                  " -ForegroundColor DarkCyan

# === PARAMETERS ===
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "JV-ServerPeriodicDiskCleanup-Log_$(Get-Date -Format dd-MM-yyyy).txt"

# === END PARAMETERS ===

function Log-DiskSpace {
    param(
        [string]$logFilePath,
        [string]$label
    )

    $drives = Get-PSDrive -PSProvider 'FileSystem'
    foreach ($drive in $drives) {
        $freeGB = "{0:N2}" -f ($drive.Free / 1GB)
        $usedGB = "{0:N2}" -f (($drive.Used) / 1GB)
        $totalGB = "{0:N2}" -f ($drive.Used + $drive.Free / 1GB)
        $logLine = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $label | Drive $($drive.Name): Free: $freeGB GB, Used: $usedGB GB, Total: $totalGB GB"
        Add-Content -Path $logFilePath -Value $logLine
    }
}

function Trim-LogFile {
    param(
        [string]$logFilePath,
        [int]$maxSizeKB = 100
    )

    if (Test-Path $logFilePath) {
        $fileInfo = Get-Item $logFilePath
        while ($fileInfo.Length -gt ($maxSizeKB * 1024)) {
            $lines = Get-Content $logFilePath
            $lines = $lines[10..($lines.Length - 1)]
            Set-Content -Path $logFilePath -Value $lines
            $fileInfo = Get-Item $logFilePath
        }
    }
}

# Step 1: First check if the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script must be runned as Administrator. The script will now end."
    exit
}


# Step 2: Logging will be enabled for checking the functionality of the script, even after it ran unattended.
function Log {
    param ($message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}
Log ""

# Step 3: Disk Cleanup of Windows volume
Log "=== STEP 3: WINDOWS DISK CLEANUP ==="

$SageSetID = 100
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sageset:$SageSetID" -WindowStyle Hidden -Wait
Start-Sleep -Seconds 2
Get-ChildItem $regPath | ForEach-Object {
    try {
        New-ItemProperty -Path $_.PSPath -Name "StateFlags$SageSetID" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

Trim-LogFile -logFilePath $logFile
Log-DiskSpace -logFilePath $logFile -label "Before Cleanmgr"
$maxDuration = 1800
$attempts = 0
$maxAttempts = 2
while ($attempts -lt $maxAttempts) {
    $process = Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:$SageSetID" -PassThru
    $startTime = Get-Date

    while (-not $process.HasExited) {
        Start-Sleep -Seconds 10
        if ((New-TimeSpan -Start $startTime -End (Get-Date)).TotalSeconds -gt $maxDuration) {
            Write-Host "cleanmgr.exe takes too long. Process will be restarted." -ForegroundColor Yellow
            Stop-Process -Id $process.Id -Force
            break
        }
        Log-DiskSpace -logFilePath $logFile -label "After Cleanmgr"
        Trim-LogFile -logFilePath $logFile
    }

    if ($process.HasExited -and $process.ExitCode -eq 0) {
        Write-Host "cleanmgr.exe is has been succesfully executed." -ForegroundColor Green
        break
    }
        Log-DiskSpace -logFilePath $logFile -label "After Cleanmgr"
        Trim-LogFile -logFilePath $logFile else {
        Write-Host "cleanmgr.exe will be start again (attempt $($attempts + 2))." -ForegroundColor Yellow
    }

    $attempts++
}


#Step 4: Disk Cleanup of non-Windows volumes
Log "=== STEP 4: NON-WINDOWS DISK CLEANUP ==="

$drives = Get-PSDrive -PSProvider 'FileSystem' | Where-Object {
    $_.Free -ne $null -and $_.Name -ne 'C'
}

foreach ($drive in $drives) {
    Log "--- Volume $($drive.Name): Cleaning ---"

    $temp = "$($drive.Root)Temp"
    if (Test-Path $temp) {
        Log " - Removing temporary files"
        Get-ChildItem -Path $temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    $recycle = "$($drive.Root)\`$Recycle.Bin"
    if (Test-Path $recycle) {
        Log " - Emptying Recycle Bin"
        Get-ChildItem -Path $recycle -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    $winOld = "$($drive.Root)Windows.old"
    if (Test-Path $winOld) {
        Log " - Deleting Windows.old"
        Remove-Item -Path $winOld -Recurse -Force -ErrorAction SilentlyContinue
    }

    $wu = "$($drive.Root)Windows\SoftwareDistribution\Download"
    if (Test-Path $wu) {
        Log " - Removing Windows Update cache"
        Get-ChildItem -Path $wu -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    $do = "$($drive.Root)ProgramData\Microsoft\Network\Downloader"
    if (Test-Path $do) {
        Log " - Deleting Delivery Optimization files"
        Get-ChildItem -Path $do -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    Log " --- Volume $($drive.Name) cleanup completed ---"
}


# Step 5: Windows Event Log cleaning
Log "=== STEP 5: WINDOWS EVENT LOG CLEANING ==="

Log " - Clearing Event Logs (excluding restricted ones)"
$excludedLogs = @("Microsoft-Windows-LiveId/Analytic", "Microsoft-Windows-LiveId/Operational")
wevtutil el | Where-Object { $excludedLogs -notcontains $_ } | ForEach-Object {
    try { wevtutil cl $_ } catch {}
}


# Step 6: Removing unused device drivers
Log "=== STEP 6: REMOVING UNUSED DEVICE DRIVERS ==="
$drivers = pnputil /enum-drivers | Select-String "Published Name" | ForEach-Object {
    ($_ -split ": ")[1]
}
foreach ($driver in $drivers) {
    try {
        pnputil /delete-driver $driver /uninstall /force | Out-Null
    } catch {}
}


# Step 7: Removing Browser cache for Chrome and Edge
Log "=== STEP 7: REMOVING BROWSER CACHE ==="
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
if (Test-Path $chrome) {
    Log " - Deleting Chrome cache"
    Remove-Item "$chrome\*" -Recurse -Force -ErrorAction SilentlyContinue
}

$edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
if (Test-Path $edge) {
    Log " - Deleting Edge cache"
    Remove-Item "$edge\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 8: Rebooting server to optimize performance
Log "=== STEP 8: SCRIPT COMPLETE< REBOOTING SERVER NOW ==="
Restart-Computer -Force
