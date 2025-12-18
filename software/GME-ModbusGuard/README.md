# GME ModGuard (portable)

Minimal Modbus TCP poller with a built-in local web dashboard.

## Run
Run `GME-ModGuard.exe`.

If launched without arguments, you may be prompted for an HTTP port. For unattended use:
```
.\GME-ModGuard.exe --port 8082 --no-prompt
```
Then open `http://127.0.0.1:8082`.

### Options
- `--port <n>`: HTTP port for the web UI (default `8082`)
- `--host <ip>`: bind address (default `127.0.0.1`)
- `--no-prompt`: don’t prompt for a port; use defaults/args

## Features
- Add multiple targets (IP/port/unit id/start/count/interval)
- Reads holding registers (function 3) continuously
- Shows live values, error counts, and rolling event log
- Persists targets to `config.json` (created when you add targets)

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
