# RDP Disconnect Watcher (GME-RDPDisc)

Lightweight Windows background monitor that clears abandoned RDP sessions before they starve headless systems of RAM. Designed for kiosks, IPCs, remote support servers and other unattended hosts bundled with the Offline-ready commissioning toolkit.

`GME-RDPDisc/` ships the scheduled task that polls `qwinsta`, journals memory snapshots and uses `rwinsta` to release sessions that stay disconnected past the grace window. It has been verified stable for three straight days on a headless Windows 10 build, consistently recovering roughly 1024 MB for every abandoned session and returning available RAM to ~4.9 GB after each cleanup.

## What problem it solves
- Disconnected (`Disc`) RDP sessions stay logged in, continue to own ~1024 MB of RAM per user on the reference Windows 10 headless build and accumulate indefinitely.
- Manual cleanup via `rwinsta` is error-prone and rarely executed.
- Excess abandoned sessions can drive memory pressure and instability over time.

The watcher polls sessions, applies a grace period and resets only stale user sessions. Each cleanup is logged together with a memory snapshot for auditing.

## How it works
1. **Session monitoring**  
   Runs on a configurable loop (`PollSeconds`, default 60) and parses `qwinsta` output. It only tracks sessions that:
   - have a valid non-zero ID,
   - have a user attached,
   - are currently in the `Disc` state.  
   Service/system sessions are ignored.
2. **Grace period handling**  
   The first time a session is seen as disconnected, a timer starts. If the user reconnects, the timer is cleared. Remaining disconnected beyond `DisconnectGraceMinutes` (default 10) triggers cleanup.
3. **Memory snapshot + cleanup**  
   `systeminfo | findstr "Total Physical Memory" "Available Physical Memory"` is executed to capture before/after RAM. The log records the snapshot and the associated `rwinsta <SessionID>` call that releases the session.
4. **Logging and rotation**  
   Entries are appended to `C:\Scripts\Logs\rdp_disconnect_watch.log`. When the file exceeds `MaxLogSizeMB` (default 5 MB) it is rotated, keeping `MaxArchives` (default 10) historical files.

## Files in this folder
| File | Purpose |
| --- | --- |
| `RDPDisc-install.bat` | Text-based installer menu with shortcuts for writing the watcher, installing/updating the scheduled task, running dry runs and starting/stopping the task. |
| `RdpDiscinstaller.ps1` | Core installer used by the batch menu. Handles folder creation, watcher generation, scheduled task registration, log rotation settings and one-time test runs. |
| `SSH cmd Memory on RDP.txt` | Handy command snippet to remotely query RAM usage via SSH (`cmd /c systeminfo | findstr ...`). |

The installer writes the worker script to `C:\Scripts\RdpDiscWatch.ps1` and creates the log at `C:\Scripts\Logs\rdp_disconnect_watch.log`.

## Installation and operation
1. **Run `RDPDisc-install.bat`**  
   Launch normally to explore, or choose option 12 to relaunch elevated when you need to install/start/stop the scheduled task.
2. **Typical workflow**  
   - Option 5 ("Full install") creates folders, writes the watcher, registers the scheduled task and starts it immediately.
   - Option 6 ("One-time test run") executes the watcher with `ForceCleanup + RunOnce`, immediately clearing all disconnected sessions and logging RAM usage for commissioning.
3. **Scheduled task details**  
   - Task name: `RDP Disconnect Watcher`  
   - Runs as the `SYSTEM` account at boot, hidden, highest privileges.  
   - Command: `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Scripts\RdpDiscWatch.ps1" ...`

You can rerun option 2 to rewrite the watcher after editing defaults in the installer, rerun option 3/4 to update the task definition and option 9 to remove it entirely.

## Configuration knobs
All of the following parameters are exposed in `RdpDiscinstaller.ps1`:

| Parameter | Default | Description |
| --- | --- | --- |
| `ScriptsDir` | `C:\Scripts` | Destination for the watcher script. |
| `LogDir` | `C:\Scripts\Logs` | Location for the rotating log files. |
| `PollSeconds` | `60` | Delay between `qwinsta` polls while running continuously. |
| `DisconnectGraceMinutes` | `10` | Inactivity window before a disconnected session is reset. |
| `MaxLogSizeMB` | `5` | Threshold before rotation occurs. |
| `MaxArchives` | `10` | How many rotated log files to keep. |

Change defaults by editing the parameters passed within the batch menu or invoking the PowerShell installer directly.

## Field validation
- Verified stable for **3 consecutive days** on a headless Windows 10 testbed.
- Before the watcher runs, each disconnected Administrator session consumes roughly **1024 MB** of RAM.
- After cleanup, available physical memory consistently rebounds to the 4.9-5.0 GB range, confirming the resources are reclaimed.

### Sample log excerpt
```
[12/19/2025 11:01:14 AM] TIMEOUT: User=Administrator ID=3 -> rwinsta
[12/19/2025 11:01:14 AM] Total Physical Memory:     7,934 MB
[12/19/2025 11:01:14 AM] Available Physical Memory: 4,942 MB
[12/19/2025 2:58:24 PM] TIMEOUT: User=Administrator ID=4 -> rwinsta
[12/19/2025 2:58:24 PM] Total Physical Memory:     7,934 MB
[12/19/2025 2:58:24 PM] Available Physical Memory: 4,899 MB
[12/22/2025 12:32:23 PM] TIMEOUT: User=Administrator ID=5 -> rwinsta
[12/22/2025 12:32:23 PM] Total Physical Memory:     7,934 MB
[12/22/2025 12:32:23 PM] Available Physical Memory: 4,965 MB
[12/23/2025 7:04:19 PM] TIMEOUT: User=Administrator ID=6 -> rwinsta
[12/23/2025 7:04:19 PM] Total Physical Memory:     7,934 MB
[12/23/2025 7:04:19 PM] Available Physical Memory: 4,893 MB
```

Each `TIMEOUT` reflects a session that remained disconnected past the grace period. The accompanying memory snapshot documents the system state prior to `rwinsta`, providing an auditable trail for operators.

## Safety principles
- Only user sessions with non-zero IDs in the `Disc` state are touched.
- Service sessions, console session 0 and active sessions are skipped.
- All destructive actions (`rwinsta`) and errors are logged.
- Installation is deliberate: no scheduled task is created or altered unless an installer option explicitly requests it.

## One-time commissioning test
To prove the watcher before enabling scheduled mode:
1. Run option 6 in `RDPDisc-install.bat`.
2. The PowerShell installer runs the watcher with `-ForceCleanup -RunOnce`, immediately clearing every disconnected session.
3. Review `C:\Scripts\Logs\rdp_disconnect_watch.log` for the same memory snapshot format shown above.

This mode exits after the single pass, making it safe to run during commissioning or support calls.
