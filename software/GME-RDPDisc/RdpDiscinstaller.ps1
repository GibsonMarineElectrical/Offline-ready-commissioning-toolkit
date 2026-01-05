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

# ---------------- EASY CONFIG (edit here) ----------------
# RAM gate: enforcement only when Available RAM is BELOW this threshold (MB)
$RamThresholdMB = 2048

# Default deny (never reset these users)
$DenyUsers = @("Administrator", "Partrac_admin")

# Allowlist-only enforcement:
# Only these users are eligible for cleanup.
# If empty, watcher runs in AUDIT-ONLY mode (no rwinsta except ForceCleanup test runs).
$AllowUsers = @()
# ---------------------------------------------------------

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

    # Policy
    [int]$RamThresholdMB = 2048,
    [string[]]$AllowUsers = @(),
    [string[]]$DenyUsers = @("Administrator","Partrac_admin"),

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

function Get-AvailableRamMB {
    # Win32_OperatingSystem FreePhysicalMemory is KB
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return [int][math]::Floor(($os.FreePhysicalMemory / 1024))
    } catch {
        return -1
    }
}

function Get-SystemInfoMemoryLines {
    & cmd /c 'systeminfo | findstr /C:"Total Physical Memory" /C:"Available Physical Memory"' 2>$null
}

function Is-DeniedUser([string]$u) {
    if ([string]::IsNullOrWhiteSpace($u)) { return $true }
    foreach ($d in $DenyUsers) {
        if ($u -ieq $d) { return $true }
    }
    return $false
}

function Is-AllowedUser([string]$u) {
    if ($AllowUsers -eq $null -or $AllowUsers.Count -eq 0) { return $false }
    foreach ($a in $AllowUsers) {
        if ($u -ieq $a) { return $true }
    }
    return $false
}

$disconnectStart = @{}
$grace = if ($ForceCleanup.IsPresent) {
    New-TimeSpan -Seconds 0
} else {
    New-TimeSpan -Minutes $DisconnectGraceMinutes
}

$enforcementEnabled =
    ($ForceCleanup.IsPresent) -or (
        ($RamThresholdMB -gt 0) -and
        ($AllowUsers -ne $null) -and
        ($AllowUsers.Count -gt 0)
    )

Write-LogLine ("[{0}] START: Poll={1}s GraceMin={2} RamThresholdMB={3} EnforcementEnabled={4} ForceCleanup={5} RunOnce={6} AllowUsers={7} DenyUsers={8}" -f `
    (Get-Date), $PollSeconds, $DisconnectGraceMinutes, $RamThresholdMB, $enforcementEnabled, $ForceCleanup.IsPresent, $RunOnce.IsPresent, `
    (($AllowUsers -join ",") -replace '\s+$',''), (($DenyUsers -join ",") -replace '\s+$','')
)

while ($true) {
    try {
        Rotate-LogIfNeeded
        $now = Get-Date
        $sessions = Get-QwinstaSessions

        $availMB = Get-AvailableRamMB

        # Log the RAM gate decision context every loop (audit trail)
        if ($availMB -ge 0) {
            Write-LogLine ("[{0}] RAM: AvailMB={1} ThresholdMB={2} GateActive={3}" -f `
                $now, $availMB, $RamThresholdMB, ($availMB -lt $RamThresholdMB))
        } else {
            Write-LogLine ("[{0}] RAM: AvailMB=UNKNOWN ThresholdMB={1} GateActive=UNKNOWN" -f `
                $now, $RamThresholdMB)
        }

        foreach ($s in $sessions) {

            # Safety: only real user sessions
            if ($s.Id -le 0) { continue }
            if ([string]::IsNullOrWhiteSpace($s.UserName)) { continue }

            if ($s.State -ne "Disc") {
                $disconnectStart.Remove($s.Id) | Out-Null
                continue
            }

            $user = $s.UserName
            $id   = $s.Id

            # Start timer when first seen disconnected
            if (-not $disconnectStart.ContainsKey($id)) {
                $disconnectStart[$id] = $now
            }

            $discFor = ($now - $disconnectStart[$id])
            $discForMin = [int][math]::Floor($discFor.TotalMinutes)

            # Default deny
            if (Is-DeniedUser $user) {
                Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} Action=SKIP Reason=DefaultDeny" -f `
                    $now, $user, $id, $discForMin)
                continue
            }

            # Allowlist-only enforcement (unless ForceCleanup)
            $isAllowed = Is-AllowedUser $user
            if (-not $ForceCleanup.IsPresent -and -not $isAllowed) {
                Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} Action=SKIP Reason=NotInAllowList" -f `
                    $now, $user, $id, $discForMin)
                continue
            }

            # If not configured, audit only
            if (-not $ForceCleanup.IsPresent -and -not $enforcementEnabled) {
                Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} Action=SKIP Reason=EnforcementDisabled(AllowListEmptyOrThresholdInvalid)" -f `
                    $now, $user, $id, $discForMin)
                continue
            }

            # Grace window
            if (-not $ForceCleanup.IsPresent -and $discFor -lt $grace) {
                Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} Action=SKIP Reason=WithinGrace(GraceMin={4})" -f `
                    $now, $user, $id, $discForMin, $DisconnectGraceMinutes)
                continue
            }

            # RAM gate
            if (-not $ForceCleanup.IsPresent) {
                if ($availMB -lt 0) {
                    Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} AvailMB=UNKNOWN Action=SKIP Reason=RamCheckFailed" -f `
                        $now, $user, $id, $discForMin)
                    continue
                }

                if ($availMB -ge $RamThresholdMB) {
                    Write-LogLine ("[{0}] DECISION: User={1} ID={2} State=Disc DiscForMin={3} AvailMB={4} ThresholdMB={5} Action=SKIP Reason=RamAboveThreshold" -f `
                        $now, $user, $id, $discForMin, $availMB, $RamThresholdMB)
                    continue
                }

                Write-LogLine ("[{0}] GATEPASS: User={1} ID={2} DiscForMin={3} AvailMB={4} ThresholdMB={5} Reason=RamBelowThreshold" -f `
                    $now, $user, $id, $discForMin, $availMB, $RamThresholdMB)
            }

            # ForceCleanup mode (RunOnce test) keeps legacy behaviour but remains audited
            if ($RunOnce.IsPresent -and $ForceCleanup.IsPresent) {
                Write-LogLine ("[{0}] ACTION: User={1} ID={2} DiscForMin={3} -> rwinsta Reason=ForceCleanup" -f `
                    $now, $user, $id, $discForMin)

                Get-SystemInfoMemoryLines | ForEach-Object {
                    Write-LogLine ("[{0}] {1}" -f $now, $_.Trim())
                }

                & cmd /c ("rwinsta {0}" -f $id) | ForEach-Object {
                    Write-LogLine ("[{0}] rwinsta: {1}" -f $now, $_)
                }

                $disconnectStart.Remove($id) | Out-Null
                continue
            }

            # Audit-first snapshot then cleanup
            Write-LogLine ("[{0}] ACTION: User={1} ID={2} DiscForMin={3} -> rwinsta Reason=TimeoutAndRamGate" -f `
                $now, $user, $id, $discForMin)

            Get-SystemInfoMemoryLines | ForEach-Object {
                Write-LogLine ("[{0}] {1}" -f $now, $_.Trim())
            }

            & cmd /c ("rwinsta {0}" -f $id) | ForEach-Object {
                Write-LogLine ("[{0}] rwinsta: {1}" -f $now, $_)
            }

            $disconnectStart.Remove($id) | Out-Null
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

# Dan Gibson

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

        # Expand list args safely
        $allowArg = ""
        foreach ($u in $AllowUsers) { $allowArg += " -AllowUsers `"$u`"" }

        $denyArg = ""
        foreach ($u in $DenyUsers) { $denyArg += " -DenyUsers `"$u`"" }

        $args = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Watcher`" -LogDir `"$LogDir`" -PollSeconds $PollSeconds -DisconnectGraceMinutes $DisconnectGraceMinutes -RamThresholdMB $RamThresholdMB $allowArg $denyArg -MaxLogSizeMB $MaxLogSizeMB -MaxArchives $MaxArchives"

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
            "& '$Watcher' -LogDir '$LogDir' -PollSeconds 1 -DisconnectGraceMinutes 0 -ForceCleanup -RunOnce -RamThresholdMB $RamThresholdMB"
    }
}

# ---------------- execution ----------------

Say "== RDP Disc Installer =="
Say "ScriptsDir=$ScriptsDir"
Say "LogDir=$LogDir"
Say "Watcher=$Watcher"
Say "TaskName=$TaskName"
Say ("Policy: RamThresholdMB={0} AllowUsers={1} DenyUsers={2}" -f $RamThresholdMB, ($AllowUsers -join ","), ($DenyUsers -join ","))
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
