# GME NavRec (portable)

Listens for NMEA0183 over UDP/TCP, validates checksums, and logs to a local file. Web UI at `http://127.0.0.1:8084`.

## Run
Run `GME-NavRec.exe`.

If launched without arguments, you may be prompted for an HTTP port. For unattended use:
```
.\GME-NavRec.exe --port 8084 --no-prompt
```
Then open `http://127.0.0.1:8084`.

### Options
- `--port <n>`: HTTP port for the web UI (default `8084`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: don’t prompt for a port; use defaults/args

## Features
- UDP and TCP listeners (defaults 10110/10111), configurable via UI
- Counts total / good / bad sentences; shows recent lines with OK/BAD flag
- Logs to `logs/nmea_<timestamp>.log` (created under the current working directory; usually next to the EXE)
- Pure stdlib; ready for PyInstaller onefile

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
