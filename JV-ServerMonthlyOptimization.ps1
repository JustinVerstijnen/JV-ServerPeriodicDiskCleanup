# Justin Verstijnen Server Periodic Optimization Tool for the best performance
# Github page: https://github.com/JustinVerstijnen/JV-ServerMonthlyOptimization
# Let's start!
Write-Host "Script made by..." -ForegroundColor DarkCyan
Write-Host "     _           _   _        __     __            _   _  _                  
    | |_   _ ___| |_(_)_ __   \ \   / /__ _ __ ___| |_(_)(_)_ __   ___ _ __  
 _  | | | | / __| __| | '_ \   \ \ / / _ \ '__/ __| __| || | '_ \ / _ \ '_ \ 
| |_| | |_| \__ \ |_| | | | |   \ V /  __/ |  \__ \ |_| || | | | |  __/ | | |
 \___/ \__,_|___/\__|_|_| |_|    \_/ \___|_|  |___/\__|_|/ |_| |_|\___|_| |_|
                                                       |__/                  " -ForegroundColor DarkCyan

# === PARAMETERS ===
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "JV-ServerMonthlyOptimization-Log_$(Get-Date -Format dd-MM-yyyy).txt"
$TimeZoneToSet = "W. Europe Standard Time"  # Example: Amsterdam (UTC+1/UTC+2 DST)
$culture = "nl-NL"
$geoid = "176" #  Check this page: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations

# === END PARAMETERS ===


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


# Step 3: The timezone will be corrected to the script settings ensure the correct logging times are displayed
Log "=== STEP 3: TIME ZONE CHECK STARTED ==="
try {
    $currentTZ = (Get-TimeZone).Id
    Log "Current time zone: $currentTZ"
    
    if ($currentTZ -ne $TimeZoneToSet) {
        Log "Changing time zone to: $TimeZoneToSet"
        Set-TimeZone -Id $TimeZoneToSet
        Log "Time zone successfully changed to: $TimeZoneToSet"
    } else {
        Log "Time zone already set correctly. No change needed."
    }
} catch {
    Log "ERROR: Failed to set time zone to '$TimeZoneToSet'. Exception: $_"
}
Log "=== STEP 3: TIME ZONE CHECK COMPLETED ==="


# Step 4: Regional settings correction
Log "=== STEP 4: REGION SETTINGS CONFIGURATION STARTED ==="
try {
    Set-Culture -CultureInfo $culture
    Set-WinHomeLocation -GeoId $geoid
    Set-WinUserLanguageList -LanguageList $culture -Force

    Log "Culture set to: $culture"
    Log "Home location set to Netherlands (GeoID: $geoid)"
    Log "User language list updated to: $culture"
    $regPath = "HKCU:\Control Panel\International"
    Set-ItemProperty -Path $regPath -Name "sShortTime" -Value "HH:mm"
    Set-ItemProperty -Path $regPath -Name "sTimeFormat" -Value "HH:mm:ss"
    Set-ItemProperty -Path $regPath -Name "sDecimal" -Value ","
    Set-ItemProperty -Path $regPath -Name "sThousand" -Value "."
    Set-ItemProperty -Path $regPath -Name "sDate" -Value "dd-MM-yyyy"

    Log "Time format set to 24-hour (HH:mm:ss)"
    Log "Decimal separator set to ',' and thousand separator to '.'"
    Log "Date format set to dd-MM-yyyy"

    Log "Regional settings configured successfully."
} catch {
    Log "ERROR while setting regional settings: $_"
}

Log "=== STEP 4: REGION SETTINGS CONFIGURATION COMPLETED ==="


# Step 5: Disk Cleanup of Windows volume
Log "=== STEP 5: WINDOWS DISK CLEANUP ==="

$SageSetID = 100
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sageset:$SageSetID" -WindowStyle Hidden -Wait
Start-Sleep -Seconds 2
Get-ChildItem $regPath | ForEach-Object {
    try {
        New-ItemProperty -Path $_.PSPath -Name "StateFlags$SageSetID" -PropertyType DWord -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:$SageSetID" -Wait


#Step 6: Disk Cleanup of non-Windows volumes
Log "=== STEP 6: NON-WINDOWS DISK CLEANUP ==="

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


# Step 7: Windows Event Log cleaning
Log "=== STEP 7: WINDOWS EVENT LOG CLEANING ==="

Log " - Clearing Event Logs (excluding restricted ones)"
$excludedLogs = @("Microsoft-Windows-LiveId/Analytic", "Microsoft-Windows-LiveId/Operational")
wevtutil el | Where-Object { $excludedLogs -notcontains $_ } | ForEach-Object {
    try { wevtutil cl $_ } catch {}
}


# Step 8: Removing unused device drivers
Log "=== STEP 8: REMOVING UNUSED DEVICE DRIVERS ==="
$drivers = pnputil /enum-drivers | Select-String "Published Name" | ForEach-Object {
    ($_ -split ": ")[1]
}
foreach ($driver in $drivers) {
    try {
        pnputil /delete-driver $driver /uninstall /force | Out-Null
    } catch {}
}


# Step 9: Removing Browser cache for Chrome and Edge
Log "=== STEP 9: REMOVING BROWSER CACHE ==="
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


# Step 10: Microsoft Defender Full Scan
Log "=== STEP 10: RUNNING MICROSOFT DEFENDER SCAN (FULL) ==="

if (Get-Command -Name "Start-MpScan" -ErrorAction SilentlyContinue) {
    Log " - Starting full scan..."
    Start-MpScan -ScanType FullScan
    Log " - Full scan initiated. This may take a while."
} else {
    Log " - Microsoft Defender not available or module missing."
}

# Step 11: Checking and Installing the latest Windows Updates
Log "=== STEP 11: WINDOWS UPDATES ==="

try {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Log "Installing 'PSWindowsUpdate' module..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
        Log "'PSWindowsUpdate' module is now installed."
    } else {
        Log "'PSWindowsUpdate' module was already installed. Advancing to checking and installation."
    }

    Import-Module PSWindowsUpdate -Force
} catch {
    Log "ERROR: Failed to install or import PSWindowsUpdate module: $_"
    return
}

try {
    # List available updates
    $availableUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot

    if (-not $availableUpdates -or $availableUpdates.Count -eq 0) {
        Log "No updates available."
    } else {
        Log "Found $($availableUpdates.Count) update(s):"
        $availableUpdates | ForEach-Object {
            Log " - $($_.Title)"
        }

        Log "Beginning update installation..."

        foreach ($update in $availableUpdates) {
            try {
                Log "Installing update: $($update.Title)"
                $result = Install-WindowsUpdate -KBArticleID $update.KBArticleIDs -AcceptAll -IgnoreReboot -Confirm:$false -MicrosoftUpdate -Verbose:$false

                if ($result -and $result.RebootRequired) {
                    Log " -> Installed. Reboot required: $($update.Title)"
                } else {
                    Log " -> Installed successfully: $($update.Title)"
                }
            } catch {
                Log "ERROR: Failed to install update $($update.Title): $_"
            }
        }

        Log "Update installation process complete."
    }
} catch {
    Log "ERROR during Windows Update process: $_"
}
Log "=== SCRIPT COMPLETED ==="
Log "=== SERVER WILL NOW REBOOT ==="
Restart-Computer -Force