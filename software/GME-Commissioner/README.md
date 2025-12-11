# GME Commissioner (portal)

Heimdall-style landing page that keeps GME tools separate but provides one web UI. Integrated mini-tools inside this server:
- Adapter/IP snapshot (NetPulse-lite)
- Throughput soak (TCP/UDP)
- NTP query + optional PTP-style multicast beacon (path test only)
- Enclosure heat check + PTC selector

Other GME apps are listed with their EXE/script paths for manual launch (ModGuard, NavSim, NavRec, LinkGuard, NetPulse, TrafficGuard Web, Gateway, CalcServer).

## Run
```
python commissioner_server.py --port 8080
```
Then open `http://127.0.0.1:8080`. Add `--minimize-console` if you want the console minimized after launch.

## Build onefile (optional)
```
pyinstaller --onefile --console --name GME-Commissioner commissioner_server.py
```
Output lands in `dist\GME-Commissioner.exe`.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>
