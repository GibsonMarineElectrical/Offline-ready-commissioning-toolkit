# GME NetPulse (portable)

Local web dashboard showing Windows network adapter status (link speed, MAC) and IPv4 addresses.

## Run
Run `GME-NetPulse.exe` and open the URL it prints (default `http://0.0.0.0:1989`).

PowerShell example:
```
.\GME-NetPulse.exe --host 0.0.0.0 --port 1989 --no-prompt
```

### Options
- `--port <n>`: HTTP port for the web UI (default `1989`)
- `--host <ip>`: bind address (default `0.0.0.0`)
- `--no-prompt`: don’t prompt for a port; use defaults/args

## Notes
- Uses PowerShell (`Get-NetAdapter`, `Get-NetIPAddress`) to collect adapter info.
- By default it binds to `0.0.0.0` (LAN-accessible). If Windows Firewall prompts, allow only what you need, or run with `--host 127.0.0.1` for loopback-only.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>

