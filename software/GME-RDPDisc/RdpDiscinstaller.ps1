# RdpDiscinstaller.ps1
# Windows PowerShell 5.1 compatible
# All feature toggles are [switch] (OFF unless explicitly provided)

[CmdletBinding()]
param(
    # Paths / names
    [string]$ScriptsDir = "C:\Scripts",
    [string]$LogDir     = "C:\Scripts\Logs",
    [string]$TaskName   = "RDP Disconnect Watcher",

    # Feature toggles (OFF unless present)
    [switch]$DoEnsureFolders,
    [switch]$DoWriteWatcher,
    [switch]$DoInstallScheduledTask,
    [switch]$DoStartScheduledTask,
    [switch]$DoOneTimeTestRun,
    [switch]$DoDryRun,

    # Watcher config
    [int]$PollSeconds = 60,
    [int]$DisconnectGraceMinutes = 10,

    # Log rotation
    [int]$MaxLogSizeMB = 5,
    [int]$MaxArchives  = 10
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Watcher = Join-Path $ScriptsDir "RdpDiscWatch.ps1"

# ---------------- helpers ----------------

function Say([string]$msg) {
    Write-Host $msg
}

function Do-Action([string]$desc, [scriptblock]$action) {
    if ($DoDryRun.IsPresent) {
        Say "DRYRUN: $desc"
        return
    }
    Say "DO: $desc"
    & $action
}

function Ensure-Dir([string]$path) {
    Do-Action "Ensure directory exists: $path" {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

# ---------------- watcher writer ----------------

function Write-WatcherScript {

    Do-Action "Write watcher script: $Watcher" {

@'
param(
    [string]$LogDir = "C:\Logs",
    [string]$LogFileName = "rdp_disconnect_watch.log",
    [int]$PollSeconds = 60,
    [int]$DisconnectGraceMinutes = 10,
    [switch]$ForceCleanup,
    [switch]$RunOnce,
    [int]$MaxLogSizeMB = 5,
    [int]$MaxArchives = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (!(Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

$LogPath = Join-Path $LogDir $LogFileName

function Write-LogLine {
    param([string]$Line)
    $Line | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Rotate-LogIfNeeded {
    if (!(Test-Path $LogPath)) { return }
    if ((Get-Item $LogPath).Length -lt ($MaxLogSizeMB * 1MB)) { return }

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $arch  = Join-Path $LogDir ("rdp_disconnect_watch.$stamp.log")
    Move-Item $LogPath $arch -Force

    Get-ChildItem $LogDir -Filter "rdp_disconnect_watch.*.log" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip $MaxArchives |
        Remove-Item -Force
}

function Get-QwinstaSessions {
    $raw = & cmd /c "qwinsta" 2>$null
    if (!$raw) { return @() }

    $sessions = @()
    foreach ($line in ($raw | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $t = ($line.Trim() -replace '^\>','') -split '\s+'

        if ($t.Count -ge 4) {
            $sessions += [pscustomobject]@{
                SessionName = $t[0]
                UserName    = $t[1]
                Id          = [int]$t[2]
                State       = $t[3]
            }
        }
        elseif ($t.Count -eq 3) {
            $sessions += [pscustomobject]@{
                SessionName = ""
                UserName    = $t[0]
                Id          = [int]$t[1]
                State       = $t[2]
            }
        }
    }
    return $sessions
}

function Get-SystemInfoMemoryLines {
    & cmd /c 'systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"' 2>$null
}

$disconnectStart = @{}
$grace = if ($ForceCleanup.IsPresent) {
    New-TimeSpan -Seconds 0
} else {
    New-TimeSpan -Minutes $DisconnectGraceMinutes
}

Write-LogLine ("[{0}] START: Poll={1}s Grace={2} ForceCleanup={3} RunOnce={4}" -f `
    (Get-Date), $PollSeconds, $grace, $ForceCleanup.IsPresent, $RunOnce.IsPresent)

while ($true) {
    try {
        Rotate-LogIfNeeded
        $now = Get-Date
        $sessions = Get-QwinstaSessions
        $seen = @{}

        foreach ($s in $sessions) {
            if ($s.Id -le 0) { continue }
            if ([string]::IsNullOrWhiteSpace($s.UserName)) { continue }

            $seen[$s.Id] = $true

            if ($s.State -eq "Disc") {

                if ($RunOnce.IsPresent -and $ForceCleanup.IsPresent) {
                    Write-LogLine ("[{0}] FORCE: User={1} ID={2} -> rwinsta" -f $now, $s.UserName, $s.Id)
                    Get-SystemInfoMemoryLines | ForEach-Object {
                        Write-LogLine ("[{0}] {1}" -f $now, $_.Trim())
                    }
                    & cmd /c ("rwinsta {0}" -f $s.Id) | ForEach-Object {
                        Write-LogLine ("[{0}] rwinsta: {1}" -f $now, $_)
                    }
                    continue
                }

                if (-not $disconnectStart.ContainsKey($s.Id)) {
                    $disconnectStart[$s.Id] = $now
                }
                elseif (($now - $disconnectStart[$s.Id]) -ge $grace) {
                    Write-LogLine ("[{0}] TIMEOUT: User={1} ID={2} -> rwinsta" -f $now, $s.UserName, $s.Id)
                    Get-SystemInfoMemoryLines | ForEach-Object {
                        Write-LogLine ("[{0}] {1}" -f $now, $_.Trim())
                    }
                    & cmd /c ("rwinsta {0}" -f $s.Id) | ForEach-Object {
                        Write-LogLine ("[{0}] rwinsta: {1}" -f $now, $_)
                    }
                    $disconnectStart.Remove($s.Id)
                }
            }
            else {
                $disconnectStart.Remove($s.Id) | Out-Null
            }
        }

        if ($RunOnce.IsPresent) {
            Write-LogLine ("[{0}] EXIT: RunOnce" -f (Get-Date))
            break
        }

        Start-Sleep -Seconds $PollSeconds
    }
    catch {
        Write-LogLine ("[{0}] ERROR: {1}" -f (Get-Date), $_.Exception.Message)
        if ($RunOnce.IsPresent) { break }
        Start-Sleep -Seconds $PollSeconds
    }
}
'@ | Set-Content -Path $Watcher -Encoding UTF8 -Force

    }
}

# ---------------- scheduled task ----------------

function Install-Task {

    if (!(Test-Path $Watcher)) {
        throw "Watcher not found at $Watcher"
    }

    Do-Action "Install/replace scheduled task: $TaskName" {

        try {
            if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            }
        } catch {}

        $exe  = "powershell.exe"
        $args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Watcher`" -LogDir `"$LogDir`" -PollSeconds $PollSeconds -DisconnectGraceMinutes $DisconnectGraceMinutes -MaxLogSizeMB $MaxLogSizeMB -MaxArchives $MaxArchives"

        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action (New-ScheduledTaskAction -Execute $exe -Argument $args) `
            -Trigger (New-ScheduledTaskTrigger -AtStartup) `
            -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest) `
            -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Days 3650)) `
            | Out-Null
    }
}

function Start-TaskNow {
    Do-Action "Start scheduled task now: $TaskName" {
        Start-ScheduledTask -TaskName $TaskName
    }
}

function One-Time-TestRun {

    if (!(Test-Path $Watcher)) {
        throw "Watcher not found at $Watcher"
    }

    Do-Action "One-time test run (ForceCleanup + RunOnce)" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
            "& '$Watcher' -LogDir '$LogDir' -PollSeconds 1 -DisconnectGraceMinutes 0 -ForceCleanup -RunOnce"
    }
}

# ---------------- execution ----------------

Say "== RDP Disc Installer =="
Say "ScriptsDir=$ScriptsDir"
Say "LogDir=$LogDir"
Say "Watcher=$Watcher"
Say "TaskName=$TaskName"
Say ("Toggles: EnsureFolders={0} WriteWatcher={1} InstallTask={2} StartTask={3} OneTimeTestRun={4} DryRun={5}" -f `
    $DoEnsureFolders.IsPresent, $DoWriteWatcher.IsPresent, $DoInstallScheduledTask.IsPresent, `
    $DoStartScheduledTask.IsPresent, $DoOneTimeTestRun.IsPresent, $DoDryRun.IsPresent)

if ($DoEnsureFolders) {
    Ensure-Dir $ScriptsDir
    Ensure-Dir $LogDir
}

if ($DoWriteWatcher) {
    Ensure-Dir $ScriptsDir
    Write-WatcherScript
}

if ($DoInstallScheduledTask) {
    Ensure-Dir $LogDir
    Install-Task
}

if ($DoStartScheduledTask) {
    Start-TaskNow
}

if ($DoOneTimeTestRun) {
    Ensure-Dir $LogDir
    One-Time-TestRun
}

Say "DONE."
