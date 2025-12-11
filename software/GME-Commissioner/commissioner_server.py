"""
GME Commissioner (all-in-one portal)

Heimdall-style landing page that keeps the tools separate but gives one web entrypoint.
Integrated mini-tools inside this server:
- Adapter/IP status (NetPulse-style)
- Throughput soak client/server
- NTP query + PTP-style multicast beacon (path test)
- Enclosure/heat + PTC calculators

Other GME apps are listed with their EXE paths for manual launch (keeps tools separate as requested).

Run:
    python commissioner_server.py --port 8080
Then open http://127.0.0.1:8080
"""

import argparse
import ctypes
import json
import socket
import struct
import sys
import threading
import time
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs


WEB_PORT_DEFAULT = 8080
PTP_MCAST = "224.0.1.129"
PTP_PORT = 320


def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


CONFIG_PATH = base_dir() / "commissioner_state.json"


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
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        SW_MINIMIZE = 6
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, SW_MINIMIZE)
    except Exception:
        pass


# ---------- Adapter status (NetPulse-lite) ----------
def get_adapters():
    ps_script = r"""
    $adapters = Get-NetAdapter | Where-Object { $_.Status -ne $null }
    $results = @()
    foreach ($a in $adapters) {
        $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty IPAddress
        $results += [PSCustomObject]@{
            Name = $a.Name
            Status = $a.Status
            InterfaceDescription = $a.InterfaceDescription
            LinkSpeed = $a.LinkSpeed
            MacAddress = $a.MacAddress
            AdminStatus = $a.AdminStatus
            IPs = $ips
        }
    }
    $results | ConvertTo-Json -Compress
    """
    cmd = ["powershell", "-NoProfile", "-Command", ps_script]
    try:
        raw = subprocess.check_output(cmd, encoding="utf-8", errors="ignore").strip()
    except Exception:
        return []
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data


def check_internet():
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
    for host, port in targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            continue
        finally:
            sock.close()
    return False


def build_status():
    adapters = get_adapters()
    internet_ok = check_internet()
    internet_state = "online" if internet_ok else "offline"

    results = []
    for adapter in adapters:
        name = adapter.get("Name", "Unknown")
        status = str(adapter.get("Status", "")).lower()
        admin_status = str(adapter.get("AdminStatus", "")).lower()

        if status != "up" or admin_status == "disabled":
            state = "disconnected"
        elif internet_ok:
            state = "online"
        else:
            state = "offline"

        results.append(
            {
                "name": name,
                "description": adapter.get("InterfaceDescription", ""),
                "status": adapter.get("Status", "Unknown"),
                "admin_status": adapter.get("AdminStatus", "Unknown"),
                "link_speed": adapter.get("LinkSpeed", ""),
                "mac": adapter.get("MacAddress", ""),
                "state": state,
                "ips": adapter.get("IPs", []),
            }
        )

    return {
        "internet": {"state": internet_state},
        "adapters": results,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------- NTP/PTP ----------
def ntp_query(server: str, timeout: float = 2.0):
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
    offset = ((recv_ts - t0) + (tx_ts - t1)) / 2
    delay = (t1 - t0) - (tx_ts - recv_ts)
    return {"ok": True, "tx_time": tx_ts, "recv_time": recv_ts, "offset": offset, "delay": delay}


def _ntp_ts_to_unix(seconds: int, fraction: int) -> float:
    ntp_epoch = 2208988800
    return seconds - ntp_epoch + (fraction / 2**32)


class PTPBroadcaster:
    def __init__(self, mcast_addr=PTP_MCAST, port=PTP_PORT):
        self.mcast_addr = mcast_addr
        self.port = port
        self.seq = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except Exception:
            pass

    def send(self, when: float, domain: int = 0, source: str = "commissioner") -> dict:
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


# ---------- Throughput soak ----------
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


# ---------- Enclosure / PTC ----------
def enclosure_calc(payload: dict):
    ambient = float(payload.get("ambient", 25))
    watts = float(payload.get("watts", 0))
    volume_l = float(payload.get("volume_l", 20))
    material = str(payload.get("material", "steel")).lower()
    equip = payload.get("equipment", [])

    volume_m3 = max(volume_l / 1000.0, 0.001)
    surface_area = max((volume_m3 ** (2 / 3)) * (6 ** (1 / 3)), 0.1)
    h_map = {"steel": 6.0, "stainless": 5.5, "aluminium": 8.0, "aluminum": 8.0, "plastic": 3.5}
    h_coeff = h_map.get(material, 5.0)

    delta_t = watts / (h_coeff * surface_area) if h_coeff > 0 else 0
    internal = ambient + delta_t

    equipment_eval = []
    for item in equip:
        name = str(item.get("name", "item"))
        t_min = float(item.get("min", -40))
        t_max = float(item.get("max", 70))
        ok = (internal >= t_min) and (internal <= t_max)
        equipment_eval.append(
            {"name": name, "min": t_min, "max": t_max, "within_range": ok, "margin_low": internal - t_min, "margin_high": t_max - internal}
        )

    return {
        "ambient": ambient,
        "watts": watts,
        "volume_l": volume_l,
        "material": material,
        "delta_t": delta_t,
        "internal_temp": internal,
        "equipment": equipment_eval,
        "note": "Rule-of-thumb convection estimate; add solar/cable heat externally if needed.",
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


# ---------- HTTP ----------
def json_response(handler: BaseHTTPRequestHandler, obj: dict, status: int = 200):
    data = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_html(INDEX_HTML)
            return
        if parsed.path == "/net":
            self._serve_html(NET_HTML)
            return
        if parsed.path == "/throughput":
            self._serve_html(THROUGHPUT_HTML)
            return
        if parsed.path == "/ntp":
            self._serve_html(NTP_HTML)
            return
        if parsed.path == "/thermal":
            self._serve_html(THERMAL_HTML)
            return
        if parsed.path == "/ptc":
            self._serve_html(PTC_HTML)
            return
        if parsed.path == "/filebrowser":
            self._serve_html(FILE_HTML)
            return
        if parsed.path == "/api/status":
            json_response(self, build_status())
            return
        if parsed.path == "/api/state":
            json_response(self, {"equipment": state_cache.get("equipment", []), "throughput_server": throughput_server.info()})
            return
        if parsed.path == "/api/files":
            self._handle_files(parsed)
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

    def _handle_files(self, parsed):
        qs = parse_qs(parsed.query)
        root = Path(qs.get("path", [str(base_dir())])[0]).resolve()
        if not root.exists():
            json_response(self, {"ok": False, "error": "Path not found"}, status=404)
            return
        entries = []
        try:
            for p in sorted(root.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                if p.name.startswith("."):
                    continue
                info = p.stat()
                entries.append(
                    {
                        "name": p.name,
                        "is_dir": p.is_dir(),
                        "size": info.st_size,
                        "mtime": info.st_mtime,
                        "path": str(p),
                    }
                )
        except Exception as exc:
            json_response(self, {"ok": False, "error": str(exc)}, status=500)
            return
        json_response(self, {"ok": True, "cwd": str(root), "entries": entries})

    def _serve_html(self, html_str: str):
        html = html_str.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def serve(port: int, minimize: bool):
    if minimize:
        minimize_console()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"GME Commissioner running on http://127.0.0.1:{port}")
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
  <title>GME Commissioner</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 18px; background: linear-gradient(145deg, #0f172a, #1e293b); color: #e2e8f0; }
    h1 { margin-bottom: 6px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px; }
    .card { background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 12px; box-shadow: 0 4px 14px rgba(0,0,0,0.25); }
    a { color: #38bdf8; text-decoration: none; font-weight: 700; }
    a:hover { text-decoration: underline; }
    .muted { color: #94a3b8; font-size: 13px; }
    .btn { display: inline-block; margin-top: 8px; padding: 8px 12px; background: #38bdf8; color: #0b1220; border-radius: 6px; font-weight: 700; }
  </style>
</head>
<body>
  <h1>GME Commissioner</h1>
  <p class="muted">Choose a tool. Each opens as a dedicated page. Use the home button in any page to return here.</p>
  <div class="grid">
    <div class="card"><h3>Adapters / IPs</h3><p class="muted">NetPulse-lite snapshot</p><a class="btn" href="/net">Open</a></div>
    <div class="card"><h3>Throughput Soak</h3><p class="muted">TCP/UDP server & client</p><a class="btn" href="/throughput">Open</a></div>
    <div class="card"><h3>NTP ? PTP Beacon</h3><p class="muted">Query NTP, optional PTP-style multicast</p><a class="btn" href="/ntp">Open</a></div>
    <div class="card"><h3>Enclosure Heat</h3><p class="muted">Ambient/watts/volume/material with equipment list</p><a class="btn" href="/thermal">Open</a></div>
    <div class="card"><h3>PTC Selector</h3><p class="muted">Resettable fuse sizing helper</p><a class="btn" href="/ptc">Open</a></div>
    <div class="card"><h3>File Browser</h3><p class="muted">Read-only listing (Gateway-lite)</p><a class="btn" href="/filebrowser">Open</a></div>
    <div class="card"><h3>Other GME EXEs</h3>
      <p class="muted">Manual launch (keeps tools separate)</p>
      <ul class="muted">
        <li>GME-NetPulse/dist/GME-NetPulse.exe</li>
        <li>GME-LinkGuard/dist/GME-LinkGuard.exe</li>
        <li>GME-ModGuard/dist/GME-ModGuard.exe</li>
        <li>GME-NavSim/dist/GME-NavSim.exe</li>
        <li>GME-NavRec/dist/GME-NavRec.exe</li>
        <li>GME-TrafficGuard/traffic_guard_web.py</li>
        <li>GME-CalcServer/dist/GME-CalcServer.exe</li>
      </ul>
    </div>
  </div>
</body>
</html>
"""

HEADER_BAR = """
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
    <h2 style="margin:0;">{title}</h2>
    <div>
      <a href="/" style="color:#38bdf8;text-decoration:none;font-weight:700;">Home</a>
    </div>
  </div>
"""

STYLE_BLOCK = """
  <style>
    body { font-family: Arial, sans-serif; margin: 18px; background: linear-gradient(145deg, #0f172a, #1e293b); color: #e2e8f0; }
    .card { background: #0b1220; border: 1px solid #1f2937; border-radius: 8px; padding: 12px; box-shadow: 0 4px 14px rgba(0,0,0,0.25); max-width: 1000px; }
    button { padding: 8px 12px; margin-top: 6px; cursor: pointer; border: none; border-radius: 4px; background: #38bdf8; color: #0b1220; font-weight: 700; }
    button.secondary { background: #94a3b8; color: #0b1220; }
    pre { background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 6px; overflow: auto; font-size: 13px; }
    table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 13px; }
    th, td { border: 1px solid #1f2937; padding: 6px; text-align: left; }
    th { background: #0f172a; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; margin-right: 6px; }
    .pill.up { background: #0ea5e9; color: #0b1220; }
    .pill.down { background: #ef4444; color: #0b1220; }
    .pill.offline { background: #f59e0b; color: #0b1220; }
    input, select { padding: 6px; border-radius: 4px; border: 1px solid #1f2937; width: 220px; margin-top: 4px; }
    label { display: block; margin-top: 8px; font-size: 13px; color: #cbd5e1; }
  </style>
"""


NET_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>Adapters</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="Adapters / IPs") + """
<div class="card">
  <p class="muted">NetPulse-lite snapshot (Get-NetAdapter / Get-NetIPAddress)</p>
  <button onclick="loadStatus()">Refresh</button>
  <div id="netSummary"></div>
  <table id="netTable">
    <thead><tr><th>Name</th><th>Status</th><th>Admin</th><th>Link</th><th>MAC</th><th>IPs</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<script>
async function loadStatus() {
  const res = await fetch("/api/status");
  const data = await res.json();
  const tbody = document.querySelector("#netTable tbody");
  tbody.innerHTML = "";
  const pillCls = data.internet.state === "online" ? "up" : "offline";
  document.getElementById("netSummary").innerHTML = "<div class='pill " + pillCls + "'>Internet: " + data.internet.state + "</div> <span class='muted'>" + data.timestamp + "</span>";
  (data.adapters || []).forEach((a) => {
    const tr = document.createElement("tr");
    const stateCls = a.state === "online" ? "up" : (a.state === "disconnected" ? "down" : "offline");
    tr.innerHTML = "<td>" + a.name + "</td><td><span class='pill " + stateCls + "'>" + a.state + "</span></td><td>" + a.admin_status + "</td><td>" + a.link_speed + "</td><td>" + a.mac + "</td><td>" + (a.ips||[]).join("<br>") + "</td>";
    tbody.appendChild(tr);
  });
}
loadStatus();
</script>
</body></html>
"""

THROUGHPUT_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>Throughput Soak</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="Throughput Soak") + """
<div class="card">
  <label>Protocol</label>
  <select id="svrProto"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
  <label>Port</label>
  <input id="svrPort" type="number" value="5001">
  <button onclick="startServer()">Start server</button>
  <button class="secondary" onclick="stopServer()">Stop</button>
  <label>Client host</label>
  <input id="cliHost" value="127.0.0.1">
  <label>Client port</label>
  <input id="cliPort" type="number" value="5001">
  <label>Duration (s)</label>
  <input id="cliDuration" type="number" value="5">
  <label>Packet size (bytes)</label>
  <input id="cliSize" type="number" value="1024">
  <button onclick="runClient()">Run client</button>
  <div id="svrStatus" class="muted">Stopped</div>
  <div id="cliOut" class="muted">Idle</div>
</div>
<script>
async function startServer() {
  const protocol = document.getElementById("svrProto").value;
  const port = parseInt(document.getElementById("svrPort").value || "5001", 10);
  const res = await fetch("/api/throughput/start_server", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({protocol, port})
  });
  const data = await res.json();
  document.getElementById("svrStatus").textContent = data.ok ? ("Server running " + data.status.protocol + " " + data.status.port + ", " + (data.status.bps/1e6).toFixed(2) + " Mbps") : data.message;
}

async function stopServer() {
  await fetch("/api/throughput/stop_server", {method: "POST"});
  document.getElementById("svrStatus").textContent = "Stopped";
}

async function runClient() {
  const host = document.getElementById("cliHost").value;
  const port = parseInt(document.getElementById("cliPort").value || "5001", 10);
  const duration = parseFloat(document.getElementById("cliDuration").value || "5");
  const packet_size = parseInt(document.getElementById("cliSize").value || "1024", 10);
  const protocol = document.getElementById("svrProto").value;
  const res = await fetch("/api/throughput/run_client", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({host, port, protocol, duration, packet_size})
  });
  const data = await res.json();
  if (data.ok) {
    document.getElementById("cliOut").textContent = (data.bps/1e6).toFixed(2) + " Mbps over " + data.duration.toFixed(2) + "s (sent " + data.sent_bytes + " bytes)";
  } else {
    document.getElementById("cliOut").textContent = data.error || "Client failed";
  }
}

async function bootstrap() {
  const res = await fetch("/api/state");
  const data = await res.json();
  const st = data.throughput_server || {};
  document.getElementById("svrStatus").textContent = st.running ? ("Server running " + st.protocol + " " + st.port + ", " + (st.bps/1e6).toFixed(2) + " Mbps") : "Stopped";
}
bootstrap();
</script>
</body></html>
"""

NTP_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>NTP ? PTP</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="NTP ? PTP-style Beacon") + """
<div class="card">
  <label>NTP server</label><input id="ntpServer" value="pool.ntp.org">
  <label>PTP domain</label><input id="ptpDomain" type="number" value="0">
  <label><input id="ptpSend" type="checkbox"> Also multicast PTP-style JSON</label>
  <button onclick="runNtp()">Query</button>
  <div id="ntpOut" class="muted">Waiting...</div>
</div>
<script>
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
  if (data.ntp && data.ntp.ok) {
    const offsetMs = (data.ntp.offset * 1000).toFixed(3);
    const delayMs = (data.ntp.delay * 1000).toFixed(3);
    const ptp = data.ptp && data.ptp.sent ? ("PTP beacon sent seq " + data.ptp.sequence) : (broadcast_ptp ? "PTP send failed" : "PTP send skipped");
    document.getElementById("ntpOut").innerHTML = "Offset: " + offsetMs + " ms<br>Delay: " + delayMs + " ms<br>" + ptp;
  } else {
    document.getElementById("ntpOut").textContent = (data.ntp && data.ntp.error) ? data.ntp.error : "NTP failed";
  }
}
</script>
</body></html>
"""

THERMAL_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>Enclosure Heat</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="Enclosure Heat Check") + """
<div class="card">
  <label>Ambient (degC)</label><input id="amb" type="number" value="35">
  <label>Internal dissipation (W)</label><input id="watts" type="number" value="20">
  <label>Volume (liters)</label><input id="vol" type="number" value="20">
  <label>Material</label>
  <select id="mat"><option>steel</option><option>stainless</option><option>aluminium</option><option>plastic</option></select>
  <button onclick="calcEnclosure()">Calculate</button>
  <div id="encOut" class="muted">Waiting...</div>
</div>
<div class="card">
  <h4>Equipment list</h4>
  <label>Name</label><input id="eqName">
  <label>Min degC</label><input id="eqMin" type="number" value="-20">
  <label>Max degC</label><input id="eqMax" type="number" value="60">
  <button onclick="addEquip()">Add item</button>
  <div id="eqList" class="muted">[]</div>
</div>
<script>
let equipment = [];

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
  const equip = (data.equipment||[]).map(e => "<tr><td>" + e.name + "</td><td>" + e.min + "</td><td>" + e.max + "</td><td>" + (e.within_range ? "OK" : "FAIL") + "</td><td>" + e.margin_low.toFixed(2) + "</td><td>" + e.margin_high.toFixed(2) + "</td></tr>").join("");
  document.getElementById("encOut").innerHTML = "Internal: " + data.internal_temp.toFixed(2) + " ?C (?T " + data.delta_t.toFixed(2) + " ?C) | note: " + data.note + (equip ? "<table><thead><tr><th>Name</th><th>Min</th><th>Max</th><th>Status</th><th>Margin+</th><th>Margin-</th></tr></thead><tbody>" + equip + "</tbody></table>" : "");
}

function addEquip() {
  const name = document.getElementById("eqName").value || "item";
  const min = parseFloat(document.getElementById("eqMin").value || "-20");
  const max = parseFloat(document.getElementById("eqMax").value || "60");
  equipment.push({name, min, max});
  document.getElementById("eqList").textContent = JSON.stringify(equipment, null, 2);
}

async function bootstrap() {
  const res = await fetch("/api/state");
  const data = await res.json();
  equipment = data.equipment || [];
  document.getElementById("eqList").textContent = JSON.stringify(equipment, null, 2);
}
bootstrap();
</script>
</body></html>
"""

PTC_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>PTC Selector</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="PTC Selector") + """
<div class="card">
  <label>Load current (A)</label><input id="ptcLoad" type="number" value="1.2">
  <label>Surge/inrush (A)</label><input id="ptcSurge" type="number" value="2.0">
  <label>Supply voltage (V)</label><input id="ptcVolt" type="number" value="24">
  <label>Safety factor</label><input id="ptcSF" type="number" value="1.25" step="0.05">
  <button onclick="runPTC()">Recommend</button>
  <div id="ptcOut" class="muted">Waiting...</div>
</div>
<script>
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
  const r = data.recommendation || {};
  document.getElementById("ptcOut").textContent = "I_hold ? " + r.i_hold_min + " A, I_trip ? " + r.i_trip_min + " A, V_rating ? " + r.voltage_rating_min + " V";
}
</script>
</body></html>
"""

FILE_HTML = """<!doctype html>
<html><head><meta charset="utf-8" /><title>File Browser</title>""" + STYLE_BLOCK + """</head>
<body>
""" + HEADER_BAR.format(title="File Browser (read-only)") + """
<div class="card">
  <label>Path</label><input id="pathBox" style="width:420px;">
  <button onclick="load()">List</button>
  <table id="fileTable">
    <thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th>Path</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<script>
async function load() {
  const path = document.getElementById("pathBox").value || "";
  const res = await fetch("/api/files?path=" + encodeURIComponent(path));
  const data = await res.json();
  const tbody = document.querySelector("#fileTable tbody");
  tbody.innerHTML = "";
  if (!data.ok) {
    tbody.innerHTML = "<tr><td colspan=5>" + (data.error || 'Error') + "</td></tr>";
    return;
  }
  document.getElementById("pathBox").value = data.cwd;
  (data.entries||[]).forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = "<td>" + e.name + "</td><td>" + (e.is_dir ? 'dir' : 'file') + "</td><td>" + e.size + "</td><td>" + new Date(e.mtime*1000).toLocaleString() + "</td><td>" + e.path + "</td>";
    tbody.appendChild(tr);
  });
}
load();
</script>
</body></html>
"""






def main():
    parser = argparse.ArgumentParser(description="GME Commissioner portal")
    parser.add_argument("--port", type=int, default=WEB_PORT_DEFAULT, help="HTTP port (default 8080)")
    parser.add_argument("--minimize-console", action="store_true", help="Minimize console after launch")
    args = parser.parse_args()
    serve(args.port, minimize=args.minimize_console)


if __name__ == "__main__":
    main()
