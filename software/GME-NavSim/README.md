# GME NavSim (portable)

HDT/HDG generator with a local web UI.

## Run
Start `GME-NavSim.exe`.

Open `http://127.0.0.1:8081`.

PowerShell example:
```powershell
.\GME-NavSim.exe --port 8081 --no-prompt
```

## Options
- `--port <n>`: HTTP port for the web UI (default `8081`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: do not prompt for a port; use defaults or args

## Features
- Generates HDT and HDG at a configurable rate (Hz)
- Heading sweep via step-per-tick (deg), optional magnetic variation
- Custom talker ID (example: HE, GP, GN)
- Outputs to TCP (default `20220`) or UDP (default `127.0.0.1:10110`)
- Start/stop controls plus live preview in the browser
