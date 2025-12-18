# Software

All tools live under `software/`. Each tool has its own folder with a `README.md`.

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
| GME TrafficGuard | `GME-TrafficGuard/` | N/A | N/A | PCAP usage analyser (GUI). |
| GME Gateway | `GME-Gateway/` | `1885` | `127.0.0.1` | Loopback-only file browser for offline hosting. |

## Executables
EXEs are shipped via GitHub Releases. This repository keeps documentation plus usage notes.

## Third-party software
`other-public-software/` contains third-party executables used on some projects. Confirm redistribution terms before sharing outside your organisation.

