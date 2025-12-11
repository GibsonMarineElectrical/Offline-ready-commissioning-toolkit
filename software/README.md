# GME Commissioning Toolkit (Portable)

Portable utilities for Gibson Marine Electrical LTD. All binaries are self-contained Windows EXEs living alongside their source.

## Apps
- `GME-ModGuard/` — Modbus TCP poller with web UI (`GME-ModGuard.exe`).
- `GME-NavSim/` — HDT/HDG NMEA generator with web UI (`GME-NavSim.exe`).
- `GME-LinkGuard/` — LAN health (error/discard deltas) web UI (`GME-LinkGuard.exe`).
- `GME-NavRec/` — NMEA UDP/TCP recorder with web UI (`GME-NavRec.exe`).
- `GME-NetPulse/` — Network adapter status dashboard with IPs (`GME-NetPulse.exe`).
- `GME-TrafficGuard/` — PCAP usage analyzer; includes web server `traffic_guard_web.py` and `GME-TrafficGuard.exe`.
- `GME-Gateway/` — Read-only file browser HTTP server (`GME-Gateway.exe`).
- `GME-LegacyBrowser/` — Legacy IE launcher script.

## Usage
Run the EXE inside each app’s `dist/` (or root for GME-Gateway). Consoles print the localhost URL and LAN IPs. Most UIs are browser-based.

## Build notes
- Python apps: PyInstaller `--onefile` build scripts inside each folder.
- GME-Gateway: existing EXE stored here; .NET SDK required to republish if needed.

## Attribution
Designed and built by Dan Gibson & Codex 2025 (Gibson Marine Electrical LTD).
