# GME CalcServer (portable)

> [!WARNING]
> Work in progress. This tool is not feature-complete.

Local web UI with small commissioning calculators.

## Run
Start `GME-CalcServer.exe`.

Open `http://127.0.0.1:8090`.

PowerShell example:
```powershell
.\GME-CalcServer.exe --port 8090
```

## Options
- `--port <n>`: HTTP port for the web UI (default `8090`)
- `--minimize-console`: minimize after launch

## Runtime files
`calc_state.json` is created next to the EXE to persist state (equipment list, settings).

## Network notes
The web server binds to `0.0.0.0` by default (LAN-accessible). If Windows Firewall prompts, allow only what the job needs.

The PTP beacon is a best-effort JSON multicast on `224.0.1.129:320`. It is a wiring/path check. It is not a grandmaster.

