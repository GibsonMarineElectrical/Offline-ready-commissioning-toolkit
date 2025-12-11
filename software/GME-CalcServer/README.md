# GME CalcServer (portable)

Multi-tool commissioning calculators served locally in a browser. Includes:
- NTP query with optional PTP-style multicast beacon (path testing only, not IEEE1588-compliant).
- Link/throughput soak tool (TCP/UDP server + client).
- Enclosure heat check (ambient, watts, volume, material, equipment min/max).
- PTC (resettable fuse) selector.

## Run
```
python calc_server.py --port 8090
```
Then open `http://127.0.0.1:8090`. Use `--port` to change the HTTP port. Add `--minimize-console` if you want the console minimized after launch.

## Build onefile EXE
```
build_exe.bat
```
Outputs `dist\GME-CalcServer.exe` (portable, console visible). Use `--port` when launching the EXE to set the webserver port. Add `--minimize-console` if you want it minimized after launch.

## Notes
- State (equipment list) is persisted to `calc_state.json` next to the EXE/script.
- PTP beacon is a best-effort JSON multicast on `224.0.1.129:320` for wiring/path checks; not a full PTP grandmaster.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
