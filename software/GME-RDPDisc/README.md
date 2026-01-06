# ISSUE RAISED – In Testing Phase on Workstation with multiple services running

---

## 🔴 DO NOT DEPLOY

**This tool is not approved for production use.**

Testing on a workstation with multiple running services identified that clearing disconnected RDP sessions can also impact sessions owning active services. This may interrupt background workloads or cause unintended service outages.

Until service-safe behaviour is confirmed:
- use is limited to controlled testing only
- deployment on live or critical systems is prohibited
- further investigation and mitigation are required

**Do not deploy this tool to production environments.**

---



# RDP Disconnect Watcher (GME-RDPDisc)

A small Windows background tool that **clears old disconnected Remote Desktop (RDP) sessions** so they do not slowly use up memory on unattended systems.

It runs quietly in the background using a Scheduled Task.

---

## What it’s for

When someone disconnects from Remote Desktop, Windows often leaves their session logged in as **Disconnected**.  
Over time, multiple disconnected user sessions can build up and the system can become slow or unstable.

This tool:
- checks for **disconnected RDP user sessions**
- waits a set amount of time (a *grace period*)
- clears the session if it stays disconnected  
- **explicitly excludes protected accounts (such as `Administrator`)**
- writes a log so operators can see exactly what happened


---

## How it works (plain English)

1. **Checks sessions**  
   Every minute (by default), it runs `qwinsta` to list current RDP sessions.

2. **Waits before acting**  
   If a session is seen as *Disconnected*, it waits for a configurable grace period.

3. **Clears abandoned sessions**  
   If the session stays disconnected past the grace period, it is cleared using `rwinsta`.

4. **Records memory usage**  
   Before clearing, it records a simple memory snapshot using `systeminfo`.

5. **Writes a log**  
   Everything it does is written to a log file. Old logs are rotated automatically.

---

## Operator configuration (important)

All normal behaviour is controlled from **one place** in the installer script:

**`RdpDiscinstaller.ps1` → Operator Settings block**

This is the only section an operator should edit.

### Key setting

- **`DisconnectGraceMinutes`**  
  Controls how long a disconnected RDP session is allowed to remain before it is cleared.

**Current value:**  
- Set to **1 minute** for testing and validation.

**Before deployment:**  
- The end user **must increase this value** to suit their environment (for example 10–30 minutes).

### Example (simplified)

DisconnectGraceMinutes = 1


---

## Where the files are

- **Watcher script**  
  `C:\Scripts\RdpDiscWatch.ps1`

- **Log file**  
  `C:\Scripts\Logs\rdp_disconnect_watch.log`

---

## Installation and use

1. Run `RDPDisc-install.bat`.
2. Use the menu to:
   - install everything  
   - update settings  
   - start or stop the watcher  
   - remove it completely  

No changes are made unless you explicitly select an option.

---

## Settings (single edit location)

All normal settings are controlled in one place inside  
`RdpDiscinstaller.ps1` → **Operator Settings** block.

You can change:
- how often it checks (`PollSeconds`)
- how long it waits before clearing (`DisconnectGraceMinutes`)
- which users are never cleared (`DenyUsers`)
- log size and history (`MaxLogSizeMB`, `MaxArchives`)

---

## Sample log excerpt

- [12/22/2025 12:32:23 PM] TIMEOUT: User=Administrator ID=5 -> rwinsta
- [12/22/2025 12:32:23 PM] Total Physical Memory: 7,934 MB
- [12/22/2025 12:32:23 PM] Available Physical Memory: 4,965 MB
- [12/23/2025 7:04:19 PM] TIMEOUT: User=Administrator ID=6 -> rwinsta
- [12/23/2025 7:04:19 PM] Total Physical Memory: 7,934 MB
- [12/23/2025 7:04:19 PM] Available Physical Memory: 4,893 MB


Each `TIMEOUT` entry shows:
- which user session was cleared  
- the session ID  
- the system memory state at the time  

This provides a simple audit trail for operators and support staff.

---

## Safety principles

- Only **Disconnected** user sessions are targeted  
- Active sessions are never touched  
- System and service sessions are skipped  
- Every action and error is logged  
- Nothing is installed or removed without a deliberate menu choice  

