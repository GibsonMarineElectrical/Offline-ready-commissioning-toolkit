# Software (portable)

`software/` contains the portable Windows tools shipped with the Offline-ready commissioning toolkit.

This repository contains usage notes and supporting docs. Executables are distributed via GitHub Releases.

Source code and build scripts are maintained in a separate private repository.

## Start here
Run `GME-Commissioner/GME-Commissioner.exe`.

Open `http://127.0.0.1:8080`.

## Included tools
| Tool | Folder | Default port | Default bind | Notes |
| --- | --- | --- | --- | --- |
| GME Commissioner | `GME-Commissioner/` | `8080` | `0.0.0.0` | Portal landing page. Links the toolkit together. |
| GME CalcServer | `GME-CalcServer/` | `8090` | `0.0.0.0` | Commissioning calculators, NTP checks, soak tests. |
| GME ModGuard | `GME-ModbusGuard/` | `8082` | `127.0.0.1` | Modbus TCP poller with a local dashboard. |
| GME NavSim | `GME-NavSim/` | `8081` | `127.0.0.1` | NMEA 0183 heading generator with web UI. |
| GME NavRec | `GME-NavRec/` | `8084` | `127.0.0.1` | NMEA 0183 UDP/TCP recorder with web UI. |
| GME LinkGuard | `GME-LinkGuard/` | `8083` | `127.0.0.1` | Adapter link, error, ping dashboard. |
| GME NetPulse | `GME-NetPulse/` | `1989` | `0.0.0.0` | Network adapter and IPv4 dashboard. |
| GME RDP Disconnect Watcher | `GME-RDPDisc/` | N/A | N/A | Scheduled task that clears abandoned RDP sessions. |
| GME TrafficGuard | `GME-TrafficGuard/` | N/A | N/A | PCAP usage analyser (GUI). |
| GME Gateway | `GME-Gateway/` | `1885` | `127.0.0.1` | Loopback-only file browser for offline hosting. |

## RDP Disconnect Watcher
`GME-RDPDisc/` ships the RDP Disconnect Watcher, a scheduled task that polls `qwinsta`, journals memory snapshots, and uses `rwinsta` to release RDP sessions that stay disconnected past a grace window. Verified stable for three days on a headless Windows 10 build, recovering roughly 1024 MB per abandoned session and returning available RAM to ~4.9 GB after each cleanup. See `GME-RDPDisc/README.md` for installer menu details, configuration knobs, commissioning test steps, and log samples.

## Runtime files
Most tools create small files next to the EXE. These include logs, config, saved state. Keep the toolkit in a writable location.

## Network behaviour
Several tools expose a local web UI. Some bind to `127.0.0.1` by default. Others can bind to `0.0.0.0` for LAN access. Check each tool `README.md` before use.

## Attribution
Designed and Built by Dan Gibson with assistance from "Dex" 2025 (Gibson Marine Electrical LTD).

## Third-party installers
`other-public-software/` contains third-party executables used on some projects. Confirm redistribution terms before sharing outside your organisation.
