# GME NavRec (portable)

Listens for NMEA0183 over UDP/TCP, validates checksums, and logs to a local file. Web UI at `http://127.0.0.1:8084`.

## Run
```
python nmea_gnss_recorder.py
```
You’ll be prompted for a port (or pass `--port 8084 --no-prompt`). Opens `http://127.0.0.1:<port>`.

## Features
- UDP and TCP listeners (defaults 10110/10111), configurable via UI
- Counts total / good / bad sentences; shows recent lines with OK/BAD flag
- Logs to `logs/nmea_<timestamp>.log` in this folder
- Pure stdlib; ready for PyInstaller onefile

## Onefile build (optional)
```
pyinstaller --onefile --noconsole nmea_gnss_recorder.py
```
