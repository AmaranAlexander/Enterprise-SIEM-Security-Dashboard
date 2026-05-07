# Windows Event Log Watcher Launcher
# Run this as Administrator to access the Security log

param(
    [string[]]$Channels = @("Security", "System"),
    [int]$Interval = 10,
    [string]$Api = "http://localhost:8000",
    [switch]$DryRun,
    [int]$Backfill = 0
)

$RootDir = Split-Path $PSScriptRoot -Parent

# Check for admin rights (required for Security log)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "         The Security event log requires admin rights." -ForegroundColor Yellow
    Write-Host "         System log will still work." -ForegroundColor Gray
    Write-Host ""
    Write-Host "To run with full access, right-click PowerShell -> Run as Administrator, then:" -ForegroundColor Gray
    Write-Host "  .\scripts\start_watcher.ps1" -ForegroundColor White
    Write-Host ""
}

# Find Python
$pythonCmd = if (Get-Command py -ErrorAction SilentlyContinue) { "py" }
             elseif (Get-Command python -ErrorAction SilentlyContinue) { "python" }
             else { $null }

if (-not $pythonCmd) {
    Write-Host "ERROR: Python not found." -ForegroundColor Red
    exit 1
}

# Check API is running
try {
    $null = Invoke-RestMethod "$Api/api/health" -TimeoutSec 3
    Write-Host "[OK] SIEM backend is running" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "ERROR: SIEM backend not reachable at $Api" -ForegroundColor Red
    Write-Host "       Start it first in another terminal:" -ForegroundColor Gray
    Write-Host "         cd `"$RootDir`"" -ForegroundColor White
    Write-Host "         $pythonCmd -m backend.main" -ForegroundColor White
    Write-Host ""
    exit 1
}

# Build args — each channel must be a separate element in the array
$watcherArgs = @("$RootDir\scripts\watch_windows_events.py", "--channels")
foreach ($ch in $Channels) { $watcherArgs += $ch }
$watcherArgs += @("--interval", $Interval, "--api", $Api)
if ($DryRun)   { $watcherArgs += "--dry-run" }
if ($Backfill) { $watcherArgs += @("--backfill", $Backfill) }

Write-Host ""
Write-Host "Starting Windows Event Log watcher..." -ForegroundColor Cyan
Write-Host "  Channels: $($Channels -join ', ')" -ForegroundColor Gray
Write-Host "  Interval: ${Interval}s" -ForegroundColor Gray
Write-Host "  API:      $Api" -ForegroundColor Gray
if ($DryRun) { Write-Host "  Mode:     DRY RUN (events printed only)" -ForegroundColor Yellow }
Write-Host ""
Write-Host "Dashboard: http://localhost:5173" -ForegroundColor White
Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor Gray

& $pythonCmd $watcherArgs
