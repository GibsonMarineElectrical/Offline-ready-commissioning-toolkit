# GME TrafficGuard (portable)

Portable PCAP usage analyzer.

## What it does
- Opens classic `.pcap` files (Ethernet) and aggregates bytes/packets by IP
- Lets you label/ignore devices and export results to Excel (`.xlsx`)

## Run (GUI)
Double-click `GME-TrafficGuard.exe`, choose a `.pcap`, then use **Refresh** / **Export XLSX…**.

## Run (CLI mode)
If you provide `--pcap`, it runs headless and prints rows to the console.

Example:
```
.\GME-TrafficGuard.exe --pcap capture.pcap --export usage.xlsx --top 200
```

### Options (CLI)
- `--pcap <path>`: input PCAP file
- `--export <path>`: write an `.xlsx` export (use with `--pcap`)
- `--top <n>`: number of rows (default `1000`)
- `--watch <ISO2,...>`: optional country watchlist (e.g. `CN,RU,KP`)
- `--geodb <path>`: optional CSV GeoDB (`cidr,iso2`) for country lookups without internet

## Notes
- Classic PCAP only (PCAP-NG is not supported).
- Optional country lookups may use the internet (ip-api.com). For offline-only use, skip country lookups or provide a `--geodb` CSV.

## Support

<a href="https://www.buymeacoffee.com/gme.ltd"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff" /></a>

