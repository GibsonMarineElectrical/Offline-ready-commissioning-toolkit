# GME CalcServer (portable)

Multi-tool commissioning calculators served locally in a browser. Includes:
- NTP query with optional PTP-style multicast beacon (path testing only; not IEEE1588-compliant).
- Link/throughput soak tool (TCP/UDP server + client).
- Enclosure heat check (ambient, watts, volume, material, equipment min/max).
- PTC (resettable fuse) selector.

## Run
- Double-click `GME-CalcServer.exe`
- Or from PowerShell:
  ```
  .\GME-CalcServer.exe --port 8090
  ```
- Open `http://127.0.0.1:8090`

### Options
- `--port <n>`: HTTP port for the web UI (default `8090`)
- `--minimize-console`: minimize after launch

## Files created at runtime
- `calc_state.json` is created/updated next to the EXE to persist state (equipment list, etc).

## Notes
- The web server binds to `0.0.0.0` (LAN-accessible). If Windows Firewall prompts, allow only what you need.
- PTP beacon is a best-effort JSON multicast on `224.0.1.129:320` for wiring/path checks; not a full PTP grandmaster.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
