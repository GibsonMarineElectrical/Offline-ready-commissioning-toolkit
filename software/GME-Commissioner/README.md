# GME Commissioner (portal)

> [!WARNING]
> Work in progress. This tool is not feature-complete.

Landing page for the toolkit. It keeps each tool separate while providing a single web UI with links.

Built-in pages:
- Adapter and IP snapshot (NetPulse-lite)
- Throughput soak (TCP/UDP)
- NTP query plus optional multicast beacon (path test only)
- Enclosure heat check plus PTC selector

## Run
Start `GME-Commissioner.exe`.

Open `http://127.0.0.1:8080`.

PowerShell example:
```powershell
.\GME-Commissioner.exe --port 8080
```

## Options
- `--port <n>`: HTTP port for the portal (default `8080`)
- `--minimize-console`: minimize after launch

## Runtime files
`commissioner_state.json` is created next to the EXE to persist state.

## Notes
The portal binds to `0.0.0.0` (LAN-accessible). If Windows Firewall prompts, allow only what the job needs.

Some pages may show example paths referencing `dist/` from older builds. In this repository, the EXEs live directly in each tool folder.
