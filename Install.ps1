# === SETTINGS ===
$TaskName        = "JV-ServerPeriodicDiskCleanup-Task"
$ScriptName      = "JV-ServerPeriodicDiskCleanup.ps1"
$SourceScript    = Join-Path -Path $PSScriptRoot -ChildPath $ScriptName
$TargetFolder    = "C:\Scripts"
$TargetScript    = Join-Path -Path $TargetFolder -ChildPath $ScriptName
$RunTime         = "03:00"      # Configure the run-time here
$DayOfMonth      = "1"          # Configure the day of the month here

# === STEP 1: Copy script to C:\Scripts ===
Write-Host "Ensuring folder $TargetFolder exists..."
if (-not (Test-Path $TargetFolder)) {
    New-Item -Path $TargetFolder -ItemType Directory | Out-Null
    Write-Host "Created folder: $TargetFolder"
}

Write-Host "Copying script from '$SourceScript' to '$TargetScript'"
Copy-Item -Path $SourceScript -Destination $TargetScript -Force

# === STEP 2: Create scheduled task using schtasks.exe ===
Write-Host "Creating scheduled task..."

# Construct schtasks command
$taskCmd = @(
    "/Create",
    "/TN `"${TaskName}`"",
    "/TR `"powershell.exe -ExecutionPolicy Bypass -File `"$TargetScript`"`"",
    "/SC MONTHLY",
    "/D $DayOfMonth",  
    "/ST $RunTime",
    "/RL HIGHEST",
    "/F",
    "/RU SYSTEM"
) -join ' '

# Execute
Start-Process -FilePath schtasks.exe -ArgumentList $taskCmd -NoNewWindow -Wait
Write-Host "Scheduled task '$TaskName' created successfully via schtasks."
