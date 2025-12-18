# GME NavSim (portable)

HDT/HDG generator with a local web UI. Defaults to `http://127.0.0.1:8081`.

## Run
Run `GME-NavSim.exe`.

If launched without arguments, you may be prompted for an HTTP port. For unattended use:
```
.\GME-NavSim.exe --port 8081 --no-prompt
```
Then open `http://127.0.0.1:8081`.

### Options
- `--port <n>`: HTTP port for the web UI (default `8081`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: don’t prompt for a port; use defaults/args

## Features
- Generates HDT and HDG at a configurable rate (Hz)
- Heading sweep via step-per-tick (deg), optional magnetic variation
- Custom talker ID (e.g., HE/GP/GN)
- Outputs to TCP (default 20220) and/or UDP (default 127.0.0.1:10110)
- Start/stop and live preview from the browser; simple event log

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
