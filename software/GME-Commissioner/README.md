# GME Commissioner (portal)

Heimdall-style landing page that keeps GME tools separate but provides one web UI. Integrated mini-tools inside this server:
- Adapter/IP snapshot (NetPulse-lite)
- Throughput soak (TCP/UDP)
- NTP query + optional PTP-style multicast beacon (path test only)
- Enclosure heat check + PTC selector

Other GME apps are listed for manual launch (keeps tools separate).

## Run
Run `GME-Commissioner.exe` and then open `http://127.0.0.1:8080`.

PowerShell example:
```
.\GME-Commissioner.exe --port 8080
```

### Options
- `--port <n>`: HTTP port for the portal (default `8080`)
- `--minimize-console`: minimize after launch

## Files created at runtime
- `commissioner_state.json` is created/updated next to the EXE to persist state.

## Notes
- The portal binds to `0.0.0.0` (LAN-accessible). If Windows Firewall prompts, allow only what you need.
- Some pages may show example paths referencing `dist/` from older builds. In this repo, the EXEs live directly in each tool folder.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
