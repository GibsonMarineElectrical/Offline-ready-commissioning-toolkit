"""
Compact multi-tool web server for commissioning calculators.

Tools included:
- NTP query with optional PTP-style multicast broadcaster (best-effort, not a full IEEE1588 stack)
- Link/throughput soak (TCP/UDP) with embeddable server and client
- Enclosure heat rise check (equipment min/max vs ambient, dissipation, enclosure volume/material)
- PTC (resettable fuse) selector helper

Run:
    python calc_server.py --port 8090
Then open http://127.0.0.1:8090

All stdlib; suitable for PyInstaller onefile.
"""

import argparse
import ctypes
import json
import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


WEB_PORT_DEFAULT = 8090
PTP_MCAST = "224.0.1.129"
PTP_PORT = 320


def base_dir() -> Path:
    """Folder next to script or bundled EXE (PyInstaller-safe)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


CONFIG_PATH = base_dir() / "calc_state.json"


def load_state():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(state: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


def minimize_console():
    """Best-effort console minimize so app stays out of the way when launched manually."""
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        SW_MINIMIZE = 6
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, SW_MINIMIZE)
    except Exception:
        pass


def ntp_query(server: str, timeout: float = 2.0):
    """Return NTP time (seconds since epoch) and offset vs local clock (seconds)."""
    addr = (server, 123)
    msg = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t0 = time.time()
            s.sendto(msg, addr)
            data, _ = s.recvfrom(48)
            t1 = time.time()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if len(data) < 48:
        return {"ok": False, "error": "Short NTP reply"}

    recv_ts = _ntp_ts_to_unix(struct.unpack("!I", data[32:36])[0], struct.unpack("!I", data[36:40])[0])
    tx_ts = _ntp_ts_to_unix(struct.unpack("!I", data[40:44])[0], struct.unpack("!I", data[44:48])[0])
    # Basic NTP offset calc (RFC 5905)
    offset = ((recv_ts - t0) + (tx_ts - t1)) / 2
    delay = (t1 - t0) - (tx_ts - recv_ts)
    return {
        "ok": True,
        "tx_time": tx_ts,
        "recv_time": recv_ts,
        "offset": offset,
        "delay": delay,
    }


def _ntp_ts_to_unix(seconds: int, fraction: int) -> float:
    ntp_epoch = 2208988800  # seconds between 1900 and 1970
    return seconds - ntp_epoch + (fraction / 2**32)


class PTPBroadcaster:
    """
    Very small PTP-like multicast broadcaster.
    Not a compliant PTP grandmaster; emits JSON payloads on the PTP multicast/port.
    Intended to test network path and basic listener wiring when NTP is the time source.
    """

    def __init__(self, mcast_addr=PTP_MCAST, port=PTP_PORT):
        self.mcast_addr = mcast_addr
        self.port = port
        self.seq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except Exception:
            pass

    def send(self, when: float, domain: int = 0, source: str = "calc_server") -> dict:
        self.seq = (self.seq + 1) % 65536
        secs = int(when)
        nanos = int((when - secs) * 1_000_000_000)
        payload = {
            "ptp_like": True,
            "domain": domain,
            "sequence": self.seq,
            "seconds": secs,
            "nanoseconds": nanos,
            "source": source,
            "note": "PTP-style JSON for path testing; not IEEE1588 compliant",
        }
        data = json.dumps(payload, separators=(",", ":")).encode()
        try:
            self.sock.sendto(data, (self.mcast_addr, self.port))
            return {"sent": True, "sequence": self.seq, "bytes": len(data)}
        except Exception as exc:
            return {"sent": False, "error": str(exc)}


class ThroughputServer:
    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.stats_lock = threading.Lock()
        self.total_bytes = 0
        self.start_time = None
        self.port = None
        self.protocol = None

    def start(self, port: int, protocol: str):
        if self.thread and self.thread.is_alive():
            return False, "Server already running"
        self.stop_event.clear()
        self.total_bytes = 0
        self.start_time = time.time()
        self.port = port
        self.protocol = protocol
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True, "Started"

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.thread = None
        self.port = None
        self.protocol = None

    def _run(self):
        if self.protocol == "tcp":
            self._run_tcp()
        else:
            self._run_udp()

    def _run_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", self.port))
            s.listen(5)
            s.settimeout(1)
            while not self.stop_event.is_set():
                try:
                    conn, _ = s.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle_tcp_client, args=(conn,), daemon=True).start()

    def _handle_tcp_client(self, conn: socket.socket):
        with conn:
            while not self.stop_event.is_set():
                try:
                    data = conn.recv(64 * 1024)
                except Exception:
                    break
                if not data:
                    break
                with self.stats_lock:
                    self.total_bytes += len(data)

    def _run_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("0.0.0.0", self.port))
            s.settimeout(1)
            while not self.stop_event.is_set():
                try:
                    data, _ = s.recvfrom(64 * 1024)
                except socket.timeout:
                    continue
                except Exception:
                    break
                with self.stats_lock:
                    self.total_bytes += len(data)

    def info(self):
        running = self.thread is not None and self.thread.is_alive()
        duration = time.time() - self.start_time if running and self.start_time else 0
        bps = (self.total_bytes * 8 / duration) if duration > 0 else 0
        return {
            "running": running,
            "protocol": self.protocol,
            "port": self.port,
            "bytes": self.total_bytes,
            "bps": bps,
            "duration": duration,
        }


throughput_server = ThroughputServer()
ptp_broadcaster = PTPBroadcaster()
state_cache = load_state()


def run_client(host: str, port: int, duration: float, packet_size: int, protocol: str):
    payload = b"\x00" * packet_size
    sent_bytes = 0
    t_start = time.time()
    t_end = t_start + duration

    if protocol == "tcp":
        try:
            with socket.create_connection((host, port), timeout=3) as conn:
                while time.time() < t_end:
                    conn.sendall(payload)
                    sent_bytes += len(payload)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "sent_bytes": sent_bytes}
    else:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                while time.time() < t_end:
                    s.sendto(payload, (host, port))
                    sent_bytes += len(payload)
        except Exception as exc:
            return {"ok": False, "error": str(exc), "sent_bytes": sent_bytes}

    duration_used = max(time.time() - t_start, 0.001)
    bps = sent_bytes * 8 / duration_used
    return {"ok": True, "sent_bytes": sent_bytes, "duration": duration_used, "bps": bps}


def enclosure_calc(payload: dict):
    ambient = float(payload.get("ambient", 25))
    watts = float(payload.get("watts", 0))
    volume_l = float(payload.get("volume_l", 20))
    material = str(payload.get("material", "steel")).lower()
    equip = payload.get("equipment", [])

    volume_m3 = max(volume_l / 1000.0, 0.001)
    surface_area = max((volume_m3 ** (2 / 3)) * (6 ** (1 / 3)), 0.1)  # cube approximation
    h_map = {
        "steel": 6.0,
        "stainless": 5.5,
        "aluminium": 8.0,
        "aluminum": 8.0,
        "plastic": 3.5,
    }
    h_coeff = h_map.get(material, 5.0)  # W/m2K natural convection

    delta_t = watts / (h_coeff * surface_area) if h_coeff > 0 else 0
    internal = ambient + delta_t

    equipment_eval = []
    for item in equip:
        name = str(item.get("name", "item"))
        t_min = float(item.get("min", -40))
        t_max = float(item.get("max", 70))
        ok = (internal >= t_min) and (internal <= t_max)
        equipment_eval.append(
            {
                "name": name,
                "min": t_min,
                "max": t_max,
                "within_range": ok,
                "margin_low": internal - t_min,
                "margin_high": t_max - internal,
            }
        )

    return {
        "ambient": ambient,
        "watts": watts,
        "volume_l": volume_l,
        "material": material,
        "delta_t": delta_t,
        "internal_temp": internal,
        "equipment": equipment_eval,
        "note": "Rule-of-thumb convection estimate; add solar and cable heat externally if needed.",
    }


def ptc_calc(payload: dict):
    load_current = float(payload.get("load_current", 1.0))
    surge_current = float(payload.get("surge_current", load_current * 1.5))
    supply_voltage = float(payload.get("supply_voltage", 24.0))
    safety_factor = float(payload.get("safety_factor", 1.25))

    hold_current = load_current * safety_factor
    trip_current = max(surge_current, load_current * 2.0)
    recommended = {
        "i_hold_min": round(hold_current, 3),
        "i_trip_min": round(trip_current, 3),
        "voltage_rating_min": round(supply_voltage * 1.1, 2),
        "notes": "Choose the closest standard PTC above these mins; verify derating curves vs ambient.",
    }
    return {
        "inputs": {
            "load_current": load_current,
            "surge_current": surge_current,
            "supply_voltage": supply_voltage,
            "safety_factor": safety_factor,
        },
        "recommendation": recommended,
    }


def json_response(handler: BaseHTTPRequestHandler, obj: dict, status: int = 200):
    data = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return  # quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_index()
            return
        if parsed.path == "/api/state":
            json_response(
                self,
                {
                    "equipment": state_cache.get("equipment", []),
                    "throughput_server": throughput_server.info(),
                },
            )
            return
        self.send_error(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body.decode() or "{}")
        except Exception:
            payload = {}

        if parsed.path == "/api/ntp_ptp":
            self._handle_ntp_ptp(payload)
            return
        if parsed.path == "/api/throughput/start_server":
            port = int(payload.get("port", 5001))
            protocol = str(payload.get("protocol", "tcp")).lower()
            ok, msg = throughput_server.start(port, protocol)
            json_response(self, {"ok": ok, "message": msg, "status": throughput_server.info()})
            return
        if parsed.path == "/api/throughput/stop_server":
            throughput_server.stop()
            json_response(self, {"ok": True, "status": throughput_server.info()})
            return
        if parsed.path == "/api/throughput/run_client":
            host = payload.get("host", "127.0.0.1")
            port = int(payload.get("port", 5001))
            protocol = str(payload.get("protocol", "tcp")).lower()
            duration = float(payload.get("duration", 5))
            packet_size = max(256, min(int(payload.get("packet_size", 1024)), 64 * 1024))
            result = run_client(host, port, duration, packet_size, protocol)
            json_response(self, result)
            return
        if parsed.path == "/api/enclosure":
            result = enclosure_calc(payload)
            if "equipment" in payload:
                state_cache["equipment"] = payload["equipment"]
                save_state(state_cache)
            json_response(self, result)
            return
        if parsed.path == "/api/equipment/save":
            state_cache["equipment"] = payload.get("equipment", [])
            save_state(state_cache)
            json_response(self, {"ok": True, "equipment": state_cache.get("equipment", [])})
            return
        if parsed.path == "/api/ptc":
            json_response(self, ptc_calc(payload))
            return
        self.send_error(404, "Not found")

    def _handle_ntp_ptp(self, payload: dict):
        server = payload.get("ntp_server", "pool.ntp.org")
        domain = int(payload.get("ptp_domain", 0))
        want_ptp = bool(payload.get("broadcast_ptp", False))
        ntp_result = ntp_query(server)
        response = {"ntp": ntp_result, "ptp": None}
        if ntp_result.get("ok") and want_ptp:
            source = payload.get("ptp_source", server)
            ptp_result = ptp_broadcaster.send(ntp_result["tx_time"], domain=domain, source=source)
            response["ptp"] = ptp_result
        json_response(self, response)

    def _serve_index(self):
        html = INDEX_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def serve(port: int):
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"Calculator web server running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Commissioning Calculators</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 16px; background: #f5f7fb; }
    h1 { margin-bottom: 4px; }
    section { background: #fff; border: 1px solid #dde3eb; padding: 14px; margin-bottom: 14px; border-radius: 6px; }
    label { display: block; margin-top: 6px; font-weight: 600; }
    input, select { padding: 6px; width: 220px; }
    button { margin-top: 8px; padding: 8px 12px; cursor: pointer; }
    pre { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 6px; overflow: auto; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; }
    .card { flex: 1 1 280px; min-width: 280px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #e2e8f0; padding: 6px; font-size: 13px; }
    th { background: #f1f5f9; }
  </style>
</head>
<body>
  <h1>Commissioning Calculators</h1>
  <p>Portable utilities: NTP→PTP broadcaster (best-effort), throughput soak, enclosure heat check, and PTC selector.</p>

  <section>
    <h2>NTP → PTP-style Broadcast</h2>
    <div class="row">
      <div class="card">
        <label>NTP server</label>
        <input id="ntpServer" value="pool.ntp.org">
        <label>PTP domain</label>
        <input id="ptpDomain" type="number" value="0">
        <label><input id="ptpSend" type="checkbox"> Also broadcast PTP-style multicast</label>
        <button onclick="runNtp()">Query</button>
      </div>
      <div class="card">
        <pre id="ntpOut">Waiting…</pre>
      </div>
    </div>
  </section>

  <section>
    <h2>Link / Throughput Soak (met buoy friendly)</h2>
    <div class="row">
      <div class="card">
        <h3>Server</h3>
        <label>Protocol</label>
        <select id="svrProto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
        <label>Port</label>
        <input id="svrPort" type="number" value="5001">
        <button onclick="startServer()">Start server</button>
        <button onclick="stopServer()">Stop server</button>
        <pre id="svrStatus">Stopped</pre>
      </div>
      <div class="card">
        <h3>Client</h3>
        <label>Host</label>
        <input id="cliHost" value="127.0.0.1">
        <label>Port</label>
        <input id="cliPort" type="number" value="5001">
        <label>Protocol</label>
        <select id="cliProto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
        <label>Duration (s)</label>
        <input id="cliDuration" type="number" value="5">
        <label>Packet size (bytes)</label>
        <input id="cliSize" type="number" value="1024">
        <button onclick="runClient()">Run client</button>
        <pre id="cliOut">Idle</pre>
      </div>
    </div>
  </section>

  <section>
    <h2>Enclosure Heat Check</h2>
    <div class="row">
      <div class="card">
        <label>Ambient (degC)</label>
        <input id="amb" type="number" value="35">
        <label>Internal dissipation (W)</label>
        <input id="watts" type="number" value="20">
        <label>Volume (liters)</label>
        <input id="vol" type="number" value="20">
        <label>Material</label>
        <select id="mat">
          <option>steel</option>
          <option>stainless</option>
          <option>aluminium</option>
          <option>plastic</option>
        </select>
        <button onclick="calcEnclosure()">Calculate</button>
      </div>
      <div class="card">
        <h3>Equipment list</h3>
        <table id="eqTable">
          <thead><tr><th>Name</th><th>Min degC</th><th>Max degC</th><th></th></tr></thead>
          <tbody></tbody>
        </table>
        <button onclick="addEquip()">Add item</button>
        <pre id="encOut">Waiting...</pre>
      </div>
    </div>
  </section>

  <section>
    <h2>PTC Selector</h2>
    <div class="row">
      <div class="card">
        <label>Load current (A)</label>
        <input id="ptcLoad" type="number" value="1.2">
        <label>Surge/inrush current (A)</label>
        <input id="ptcSurge" type="number" value="2.0">
        <label>Supply voltage (V)</label>
        <input id="ptcVolt" type="number" value="24">
        <label>Safety factor</label>
        <input id="ptcSF" type="number" value="1.25" step="0.05">
        <button onclick="runPTC()">Recommend</button>
      </div>
      <div class="card">
        <pre id="ptcOut">Waiting...</pre>
      </div>
    </div>
  </section>

  <script>
    let equipment = [];

    async function runNtp() {
      const ntpServer = document.getElementById("ntpServer").value;
      const ptpDomain = parseInt(document.getElementById("ptpDomain").value || "0", 10);
      const broadcast_ptp = document.getElementById("ptpSend").checked;
      const res = await fetch("/api/ntp_ptp", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ntp_server: ntpServer, ptp_domain: ptpDomain, broadcast_ptp})
      });
      const data = await res.json();
      document.getElementById("ntpOut").textContent = JSON.stringify(data, null, 2);
    }

    async function startServer() {
      const protocol = document.getElementById("svrProto").value;
      const port = parseInt(document.getElementById("svrPort").value || "5001", 10);
      const res = await fetch("/api/throughput/start_server", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({protocol, port})
      });
      const data = await res.json();
      document.getElementById("svrStatus").textContent = JSON.stringify(data, null, 2);
    }

    async function stopServer() {
      const res = await fetch("/api/throughput/stop_server", {method: "POST"});
      const data = await res.json();
      document.getElementById("svrStatus").textContent = JSON.stringify(data, null, 2);
    }

    async function runClient() {
      const host = document.getElementById("cliHost").value;
      const port = parseInt(document.getElementById("cliPort").value || "5001", 10);
      const protocol = document.getElementById("cliProto").value;
      const duration = parseFloat(document.getElementById("cliDuration").value || "5");
      const packet_size = parseInt(document.getElementById("cliSize").value || "1024", 10);
      const res = await fetch("/api/throughput/run_client", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({host, port, protocol, duration, packet_size})
      });
      const data = await res.json();
      document.getElementById("cliOut").textContent = JSON.stringify(data, null, 2);
    }

    async function calcEnclosure() {
      const ambient = parseFloat(document.getElementById("amb").value || "25");
      const watts = parseFloat(document.getElementById("watts").value || "0");
      const volume_l = parseFloat(document.getElementById("vol").value || "20");
      const material = document.getElementById("mat").value;
      const res = await fetch("/api/enclosure", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ambient, watts, volume_l, material, equipment})
      });
      const data = await res.json();
      document.getElementById("encOut").textContent = JSON.stringify(data, null, 2);
    }

    function addEquip() {
      const name = prompt("Equipment name?");
      if (!name) return;
      const min = parseFloat(prompt("Min degC? (e.g. -20)") || "-20");
      const max = parseFloat(prompt("Max degC? (e.g. 60)") || "60");
      equipment.push({name, min, max});
      renderEquip();
    }

    function renderEquip() {
      const tbody = document.querySelector("#eqTable tbody");
      tbody.innerHTML = "";
      equipment.forEach((e, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${e.name}</td><td>${e.min}</td><td>${e.max}</td><td><button onclick="removeEquip(${idx})">X</button></td>`;
        tbody.appendChild(tr);
      });
    }

    function removeEquip(idx) {
      equipment.splice(idx, 1);
      renderEquip();
    }

    async function runPTC() {
      const load_current = parseFloat(document.getElementById("ptcLoad").value || "1");
      const surge_current = parseFloat(document.getElementById("ptcSurge").value || (load_current * 1.5));
      const supply_voltage = parseFloat(document.getElementById("ptcVolt").value || "24");
      const safety_factor = parseFloat(document.getElementById("ptcSF").value || "1.25");
      const res = await fetch("/api/ptc", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({load_current, surge_current, supply_voltage, safety_factor})
      });
      const data = await res.json();
      document.getElementById("ptcOut").textContent = JSON.stringify(data, null, 2);
    }

    async function bootstrap() {
      try {
        const res = await fetch("/api/state");
        const data = await res.json();
        equipment = data.equipment || [];
        renderEquip();
        document.getElementById("svrStatus").textContent = JSON.stringify(data.throughput_server, null, 2);
      } catch (e) {
        console.error(e);
      }
    }
    bootstrap();
  </script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Commissioning calculator web server")
    parser.add_argument("--port", type=int, default=WEB_PORT_DEFAULT, help="HTTP port (default 8090)")
    parser.add_argument(
        "--minimize-console",
        action="store_true",
        help="Minimize the console window after launch (default: keep visible)",
    )
    args = parser.parse_args()
    if args.minimize_console:
        minimize_console()
    serve(args.port)


if __name__ == "__main__":
    main()
