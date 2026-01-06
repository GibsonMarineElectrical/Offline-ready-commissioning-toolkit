# RdpDiscInstaller.ps1
# Windows PowerShell 5.1 compatible
# All feature toggles are [switch] (OFF unless explicitly provided)

[CmdletBinding()]
param(
    # Paths / names (can be overridden but normally you edit Operator Settings below)
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

    # Optional overrides (leave alone if you want one config block)
    [int]$PollSeconds,
    [int]$DisconnectGraceMinutes
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# =========================
# OPERATOR SETTINGS (EDIT ONLY THIS BLOCK)
# =========================
$Config = @{
    ScriptsDir             = "C:\Scripts"
    LogDir                 = "C:\Scripts\Logs"
    TaskName               = "RDP Disconnect Watcher"

    PollSeconds            = 60
    DisconnectGraceMinutes = 10

    MaxLogSizeMB           = 5
    MaxArchives            = 10

    # Never reset these users (case-insensitive match; supports "User" or "DOMAIN\User")
    DenyUsers              = @("Administrator") # to add more users a , after the first user, never the last
}
# =========================

# Apply operator settings unless explicitly provided via params
if (-not $PSBoundParameters.ContainsKey("ScriptsDir")) { $ScriptsDir = [string]$Config.ScriptsDir }
if (-not $PSBoundParameters.ContainsKey("LogDir"))     { $LogDir     = [string]$Config.LogDir }
if (-not $PSBoundParameters.ContainsKey("TaskName"))   { $TaskName   = [string]$Config.TaskName }

if (-not $PSBoundParameters.ContainsKey("PollSeconds"))            { $PollSeconds            = [int]$Config.PollSeconds }
if (-not $PSBoundParameters.ContainsKey("DisconnectGraceMinutes")) { $DisconnectGraceMinutes = [int]$Config.DisconnectGraceMinutes }

$MaxLogSizeMB = [int]$Config.MaxLogSizeMB
$MaxArchives  = [int]$Config.MaxArchives
$DenyUsers    = [string[]]$Config.DenyUsers

$Watcher = Join-Path $ScriptsDir "RdpDiscWatch.ps1"

# Build a safe PowerShell array literal for embedding into the watcher file
$DenyUsersLiteral =
    "@(" + (($DenyUsers | ForEach-Object { '"' + (($_) -replace '"','`"') + '"' }) -join ",") + ")"

# ---------------- helpers ----------------

function Say([string]$msg) { Write-Host $msg }

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

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Ensure-ExecutionPolicyRemoteSignedLocalMachine {
    # This must run elevated. Only run it when the installer is actually doing admin work.
    if (-not (Test-IsAdmin)) { return }

    Do-Action "Set ExecutionPolicy: RemoteSigned (LocalMachine)" {
        try {
            $current = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop
            if ($current -ne 'RemoteSigned') {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
            }
        } catch {
            Say ("WARN: Could not set ExecutionPolicy RemoteSigned (LocalMachine): {0}" -f $_.Exception.Message)
        }
    }
}

# ---------------- watcher writer ----------------

function Write-WatcherScript {
    Do-Action "Write watcher script: $Watcher" {

$watcherContent = @"
param(
    [string]`$LogDir = "$LogDir",
    [string]`$LogFileName = "rdp_disconnect_watch.log",
    [int]`$PollSeconds = $PollSeconds,
    [int]`$DisconnectGraceMinutes = $DisconnectGraceMinutes,

    # Never reset these users (case-insensitive; supports "User" or "DOMAIN\User")
    [string[]]`$DenyUsers = $DenyUsersLiteral,

    [switch]`$ForceCleanup,
    [switch]`$RunOnce,
    [int]`$MaxLogSizeMB = $MaxLogSizeMB,
    [int]`$MaxArchives = $MaxArchives
)

Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

if (!(Test-Path `$LogDir)) {
    New-Item -Path `$LogDir -ItemType Directory -Force | Out-Null
}

`$LogPath = Join-Path `$LogDir `$LogFileName

function Write-LogLine {
    param([string]`$Line)
    `$Line | Out-File -FilePath `$LogPath -Append -Encoding UTF8
}

function Write-LogBlock {
    param([string[]]`$Lines)
    foreach (`$l in `$Lines) { Write-LogLine `$l }
    Write-LogLine ""   # blank line between blocks (human-readable)
}

function Rotate-LogIfNeeded {
    if (!(Test-Path `$LogPath)) { return }
    if ((Get-Item `$LogPath).Length -lt (`$MaxLogSizeMB * 1MB)) { return }

    `$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    `$arch  = Join-Path `$LogDir ("rdp_disconnect_watch.`$stamp.log")
    Move-Item `$LogPath `$arch -Force

    Get-ChildItem `$LogDir -Filter "rdp_disconnect_watch.*.log" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip `$MaxArchives |
        Remove-Item -Force
}

function Get-QwinstaRaw {
    & cmd /c "qwinsta" 2>`$null
}

function Get-QwinstaSessions {
    `$raw = Get-QwinstaRaw
    if (!`$raw) { return @() }

    `$sessions = @()
    foreach (`$line in (`$raw | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace(`$line)) { continue }
        `$t = (`$line.Trim() -replace '^\>','') -split '\s+'

        if (`$t.Count -ge 4) {
            `$sessions += [pscustomobject]@{
                SessionName = `$t[0]
                UserName    = `$t[1]
                Id          = [int]`$t[2]
                State       = `$t[3]
            }
        }
        elseif (`$t.Count -eq 3) {
            `$sessions += [pscustomobject]@{
                SessionName = ""
                UserName    = `$t[0]
                Id          = [int]`$t[1]
                State       = `$t[2]
            }
        }
    }
    return `$sessions
}

function Get-SystemInfoMemoryLines {
    & cmd /c 'systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"' 2>`$null
}

function Get-ShortUser([string]`$u) {
    if ([string]::IsNullOrWhiteSpace(`$u)) { return "" }
    return ((`$u -split '\\')[-1])
}

function Is-DeniedUser([string]`$u) {
    if ([string]::IsNullOrWhiteSpace(`$u)) { return `$true }

    # Normalise "DOMAIN\User" -> "User"
    `$uShort = Get-ShortUser `$u

    foreach (`$d in `$DenyUsers) {
        if ([string]::IsNullOrWhiteSpace(`$d)) { continue }

        `$dShort = Get-ShortUser `$d

        # Match any sensible form (exact or short)
        if (`$u -ieq `$d) { return `$true }
        if (`$uShort -ieq `$d) { return `$true }
        if (`$u -ieq `$dShort) { return `$true }
        if (`$uShort -ieq `$dShort) { return `$true }
    }
    return `$false
}

# Boot log line (if you do not see this, the watcher is not starting)
Write-LogBlock @(
    ("[{0}] BOOT: Watcher launched. PID={1}" -f (Get-Date), `$PID)
)

`$disconnectStart = @{}
`$grace = if (`$ForceCleanup.IsPresent) {
    New-TimeSpan -Seconds 0
} else {
    New-TimeSpan -Minutes `$DisconnectGraceMinutes
}

Write-LogBlock @(
    ("[{0}] START: Poll={1}s GraceMin={2} ForceCleanup={3} RunOnce={4} DenyUsers={5}" -f `
        (Get-Date), `$PollSeconds, `$DisconnectGraceMinutes, `$ForceCleanup.IsPresent, `$RunOnce.IsPresent, (`$DenyUsers -join ","))
)

while (`$true) {
    try {
        Rotate-LogIfNeeded
        `$now = Get-Date
        `$sessions = Get-QwinstaSessions

        # If parsing yields nothing, log raw qwinsta output so you can see what changed
        if (`$sessions.Count -eq 0) {
            Write-LogLine ("[{0}] WARN: Parsed 0 sessions. Raw qwinsta output follows:" -f `$now)
            `$raw = Get-QwinstaRaw
            if (`$raw) {
                foreach (`$l in `$raw) {
                    Write-LogLine ("[{0}] qwinsta> {1}" -f `$now, `$l)
                }
            } else {
                Write-LogLine ("[{0}] qwinsta> (no output)" -f `$now)
            }
            Write-LogLine ""
        }

        foreach (`$s in `$sessions) {
            if (`$s.Id -le 0) { continue }
            if ([string]::IsNullOrWhiteSpace(`$s.UserName)) { continue }

            if (Is-DeniedUser `$s.UserName) {
                if (`$s.State -eq "Disc") {
                    Write-LogBlock @(
                        ("[{0}] ACTION: No action taken (protected user)" -f `$now),
                        ("       User:  {0}" -f `$s.UserName),
                        ("       ID:    {0}" -f `$s.Id),
                        ("       State: {0}" -f `$s.State),
                        ("       Reason: User is in DenyUsers list")
                    )
                }
                continue
            }

            if (`$s.State -eq "Disc") {

                # ForceCleanup/RunOnce test mode still respects DenyUsers (Administrator stays safe)
                if (`$RunOnce.IsPresent -and `$ForceCleanup.IsPresent) {

                    `$memBefore = @(Get-SystemInfoMemoryLines | ForEach-Object { `$_.Trim() })

                    # Perform cleanup
                    & cmd /c ("rwinsta {0}" -f `$s.Id) | Out-Null

                    `$memAfter = @(Get-SystemInfoMemoryLines | ForEach-Object { `$_.Trim() })

                    Write-LogBlock @(
                        ("[{0}] DISCONNECTED: Session cleared (test mode)" -f `$now),
                        ("       Reason: ForceCleanup + RunOnce"),
                        ("       User:   {0}" -f `$s.UserName),
                        ("       ID:     {0}" -f `$s.Id),
                        ("       Memory before:"),
                        ("         {0}" -f (`$memBefore -join "`r`n         ")),
                        ("       Memory after:"),
                        ("         {0}" -f (`$memAfter -join "`r`n         "))
                    )
                    continue
                }

                if (-not `$disconnectStart.ContainsKey(`$s.Id)) {
                    `$disconnectStart[`$s.Id] = `$now
                }
                elseif ((`$now - `$disconnectStart[`$s.Id]) -ge `$grace) {

                    `$memBefore = @(Get-SystemInfoMemoryLines | ForEach-Object { `$_.Trim() })

                    # Perform cleanup
                    & cmd /c ("rwinsta {0}" -f `$s.Id) | Out-Null

                    `$memAfter = @(Get-SystemInfoMemoryLines | ForEach-Object { `$_.Trim() })

                    Write-LogBlock @(
                        ("[{0}] DISCONNECTED: Session cleared" -f `$now),
                        ("       Reason: Disconnected longer than grace period ({0} minute(s))" -f `$DisconnectGraceMinutes),
                        ("       User:   {0}" -f `$s.UserName),
                        ("       ID:     {0}" -f `$s.Id),
                        ("       Memory before:"),
                        ("         {0}" -f (`$memBefore -join "`r`n         ")),
                        ("       Memory after:"),
                        ("         {0}" -f (`$memAfter -join "`r`n         "))
                    )

                    `$disconnectStart.Remove(`$s.Id) | Out-Null
                }
            }
            else {
                `$disconnectStart.Remove(`$s.Id) | Out-Null
            }
        }

        if (`$RunOnce.IsPresent) {
            Write-LogBlock @(
                ("[{0}] EXIT: RunOnce complete" -f (Get-Date))
            )
            break
        }

        Start-Sleep -Seconds `$PollSeconds
    }
    catch {
        # If logging fails due to file/path issues, this catch may still fail to write.
        try {
            Write-LogBlock @(
                ("[{0}] ERROR: {1}" -f (Get-Date), `$_.Exception.Message)
            )
        } catch {}
        if (`$RunOnce.IsPresent) { break }
        Start-Sleep -Seconds `$PollSeconds
    }
}
"@

$watcherContent | Set-Content -Path $Watcher -Encoding UTF8 -Force
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

        # Ensure execution policy while we're running elevated (optional but requested)
        Ensure-ExecutionPolicyRemoteSignedLocalMachine

        $exe  = "powershell.exe"
        $args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Watcher`""

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
            "& '$Watcher' -PollSeconds 1 -DisconnectGraceMinutes 0 -ForceCleanup -RunOnce"
    }
}

# ---------------- execution ----------------

Say "== RDP Disc Installer =="
Say "ScriptsDir=$ScriptsDir"
Say "LogDir=$LogDir"
Say "Watcher=$Watcher"
Say "TaskName=$TaskName"
Say ("Config: PollSeconds={0} DisconnectGraceMinutes={1} MaxLogSizeMB={2} MaxArchives={3} DenyUsers={4}" -f `
    $PollSeconds, $DisconnectGraceMinutes, $MaxLogSizeMB, $MaxArchives, ($DenyUsers -join ","))

Say ("Toggles: EnsureFolders={0} WriteWatcher={1} InstallTask={2} StartTask={3} OneTimeTestRun={4} DryRun={5}" -f `
    $DoEnsureFolders.IsPresent, $DoWriteWatcher.IsPresent, $DoInstallScheduledTask.IsPresent, `
    $DoStartScheduledTask.IsPresent, $DoOneTimeTestRun.IsPresent, $DoDryRun.IsPresent)

if ($DoEnsureFolders) {
    Ensure-Dir $ScriptsDir
    Ensure-Dir $LogDir
}

if ($DoWriteWatcher) {
    Ensure-Dir $ScriptsDir
    Ensure-Dir $LogDir
    Write-WatcherScript
}

if ($DoInstallScheduledTask) {
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
