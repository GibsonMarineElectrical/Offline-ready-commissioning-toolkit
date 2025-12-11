# GME ModGuard (portable)

Minimal Modbus TCP poller with a built-in local web dashboard.

## Run
```
python modbus_multiwatch.py
```
You'll be prompted for a port (or pass `--port 8082 --no-prompt`). Opens `http://127.0.0.1:<port>`.

## Features
- Add multiple targets (IP/port/unit id/start/count/interval)
- Reads holding registers (function 3) continuously
- Shows live values, error counts, and rolling event log
- Persists targets to `config.json` in this folder

## Building a single-file EXE (optional)
PyInstaller example:
```
pyinstaller --onefile --noconsole modbus_multiwatch.py
```

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
