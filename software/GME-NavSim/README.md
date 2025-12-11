# GME NavSim (portable)

HDT/HDG generator with a local web UI. Defaults to `http://127.0.0.1:8081`.

## Run
```
python nmea_gnss_sim.py
```
You’ll be prompted for a port (or pass `--port 8081 --no-prompt`). Opens `http://127.0.0.1:<port>`.

## Features
- Generates HDT and HDG at a configurable rate (Hz)
- Heading sweep via step-per-tick (deg), optional magnetic variation
- Custom talker ID (e.g., HE/GP/GN)
- Outputs to TCP (default 20220) and/or UDP (default 127.0.0.1:10110)
- Start/stop and live preview from the browser; simple event log

## One-file build (optional)
```
pyinstaller --onefile --noconsole nmea_gnss_sim.py
```
