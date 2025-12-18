# GME Commissioning Toolkit (Portable)

This `software/` folder is intentionally **binaries + docs only**:
- Portable Windows executables (`*.exe`)
- Per-tool `README.md` usage notes

Source code and build scripts are kept in a separate private repository.

## How it works
Most tools start a small local web server:
1. Run the `*.exe`
2. Open the shown URL (usually `http://127.0.0.1:<port>`) in your browser

Several tools create small files next to the EXE at runtime (logs/config/state). Keep the toolkit in a writable folder (not `C:\Program Files\...`).

## Included tools
- `GME-Commissioner/GME-Commissioner.exe` – Portal/landing page (links the toolkit together).
- `GME-CalcServer/GME-CalcServer.exe` – Commissioning calculators + NTP/PTP path check + soak tests.
- `GME-ModbusGuard/GME-ModGuard.exe` – Modbus TCP poller with a built-in web dashboard.
- `GME-NavSim/GME-NavSim.exe` – NMEA0183 HDT/HDG heading generator with web UI.
- `GME-NavRec/GME-NavRec.exe` – NMEA0183 UDP/TCP recorder with web UI.
- `GME-LinkGuard/GME-LinkGuard.exe` – Adapter link/error dashboard + optional ping.
- `GME-NetPulse/GME-NetPulse.exe` – Network adapter/IP dashboard.
- `GME-TrafficGuard/GME-TrafficGuard.exe` – PCAP usage analyzer (GUI).
- `GME-Gateway/GME-Gateway.exe` – Loopback-only read-only file browser (web UI).

## Offline installers
`offline-installers/` contains additional installer EXEs used alongside the toolkit.

## Attribution
Designed and built by Dan Gibson & Codex 2025 (Gibson Marine Electrical LTD).

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
