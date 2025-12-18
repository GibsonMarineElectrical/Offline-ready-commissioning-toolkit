# Offline-ready commissioning toolkit

Portable reference pack plus offline utilities used during marine and offshore FAT/SAT work when internet access is limited.

> [!WARNING]
> `GME-Commissioner` is a work in progress. It is not feature-complete. Interfaces may change.
> `GME-CalcServer` is also in active development. Expect changes.

## Quick start (Windows)
1. Download the latest release ZIP.
2. Extract it to a writable folder.
3. Start the toolkit portal: `software/GME-Commissioner/GME-Commissioner.exe`.
4. Open `http://127.0.0.1:8080` in a browser.

## Repository layout
| Path | Description |
| --- | --- |
| `docs/` | Protocol notes, safety references |
| `commissioning/` | Site scripts, configuration notes |
| `software/` | Portable Windows executables plus per-tool usage notes |

## Notes for site use
- Keep the pack on removable media or a local project folder. Avoid `C:\Program Files\...` since several tools write logs or state files next to the EXE.
- Several tools run a local web service. Review each tool `README.md` before use. Keep Windows Firewall rules tight.
- Do not store credentials. Do not store client configuration or vessel data. Do not store packet captures or logs.

## Support
No support is provided for this repository.

[![Buy me a coffee](https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=&slug=gme.ltd&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff)](https://www.buymeacoffee.com/gme.ltd)
