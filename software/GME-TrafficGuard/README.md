# GME TrafficGuard (portable)

Portable PCAP usage analyser.

## What it does
- Opens classic `.pcap` files (Ethernet)
- Aggregates bytes and packets by IP
- Supports labels and ignore rules
- Exports results to Excel (`.xlsx`)

## Run (GUI)
Double-click `GME-TrafficGuard.exe`, select a `.pcap`, use **Refresh** or **Export XLSX**.

## Run (CLI)
Provide `--pcap` to run headless. It prints rows to the console.

Example:
```powershell
.\GME-TrafficGuard.exe --pcap capture.pcap --export usage.xlsx --top 200
```

## Options (CLI)
- `--pcap <path>`: input PCAP file
- `--export <path>`: write an `.xlsx` export (use with `--pcap`)
- `--top <n>`: number of rows (default `1000`)
- `--watch <ISO2,...>`: optional country watchlist (example: `CN,RU,KP`)
- `--geodb <path>`: optional CSV GeoDB (`cidr,iso2`) for country lookups without internet

## Notes
Classic PCAP only. PCAP-NG is not supported.

Optional country lookups may use the internet (ip-api.com). For offline-only work, skip country lookups or provide a `--geodb` CSV.
