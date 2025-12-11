import argparse
import json
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import ctypes


def minimize_console():
    """Minimize the console window so the app lives on the taskbar."""
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        SW_MINIMIZE = 6
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, SW_MINIMIZE)
    except Exception:
        # Best-effort; ignore if unable to minimize.
        pass


def get_adapters():
    """Return a list of network adapters (with IPv4 addresses) from PowerShell."""
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
    except (subprocess.CalledProcessError, FileNotFoundError):
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
    """Check internet reachability via a short TCP connect."""
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


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GME NetPulse</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='12' fill='%230f1629'/><rect x='6' y='6' width='52' height='52' rx='10' fill='%236ae6ff'/><text x='50%' y='58%' text-anchor='middle' font-family='Segoe UI, Arial' font-size='26' font-weight='700' fill='%230f1629'>DG</text></svg>">
  <style>
    :root {
      --bg: #0f1629;
      --card: rgba(255, 255, 255, 0.06);
      --muted: #a9b4c8;
      --green: #4ade80;
      --orange: #f8c343;
      --red: #ff6b6b;
      --panel: linear-gradient(135deg, #111a2f 0%, #0c1b2a 50%, #10172d 100%);
      --glass: rgba(255, 255, 255, 0.08);
      --accent: #6ae6ff;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: 'Bahnschrift', 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 20% 20%, rgba(106, 230, 255, 0.12), transparent 35%),
                  radial-gradient(circle at 80% 0%, rgba(255, 107, 107, 0.12), transparent 28%),
                  var(--bg);
      color: #e7edf7;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px;
    }

    .shell {
      width: min(1100px, 100%);
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 18px;
      box-shadow: 0 20px 70px rgba(0,0,0,0.35);
      overflow: hidden;
      position: relative;
    }

    .shell::before, .shell::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 30% 20%, rgba(106, 230, 255, 0.07), transparent 35%),
                  radial-gradient(circle at 80% 30%, rgba(255, 132, 124, 0.07), transparent 32%);
      pointer-events: none;
      z-index: 0;
    }

    header {
      position: relative;
      z-index: 1;
      padding: 24px 28px 12px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
    }

    .title {
      font-size: 24px;
      letter-spacing: 0.02em;
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
    }

    .title .dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      background: var(--accent);
      box-shadow: 0 0 18px rgba(106, 230, 255, 0.6);
    }

    .meta {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      border-radius: 999px;
      background: var(--glass);
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-size: 14px;
      font-weight: 600;
    }

    .status-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      box-shadow: 0 0 14px currentColor;
    }

    .grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      padding: 0 28px 28px 28px;
    }

    .card {
      background: var(--card);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 16px;
      backdrop-filter: blur(6px);
      position: relative;
      overflow: hidden;
      transition: transform 0.25s ease, border-color 0.25s ease;
    }

    .card:hover { transform: translateY(-4px); border-color: rgba(255, 255, 255, 0.15); }

    .card h3 {
      margin: 0;
      font-size: 18px;
      letter-spacing: 0.01em;
      line-height: 1.3;
    }

    .card-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 6px;
    }

    .card .badge {
      padding: 6px 10px;
      border-radius: 10px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      white-space: nowrap;
    }

    .desc { color: var(--muted); font-size: 13px; line-height: 1.4; }

    .row {
      margin-top: 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: #dce4f5;
      font-size: 13px;
      flex-wrap: wrap;
    }

    .pill {
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      background: rgba(255, 255, 255, 0.06);
      color: #e7edf7;
      font-weight: 600;
      font-size: 12px;
      letter-spacing: 0.02em;
    }

    .note {
      color: var(--muted);
      font-size: 12px;
      padding: 0 28px 18px 28px;
      position: relative;
      z-index: 1;
    }

    .bar {
      position: absolute;
      inset: 0;
      width: 6px;
      background: var(--green);
      opacity: 0.9;
    }

    .bar.offline { background: var(--orange); }
    .bar.disconnected { background: var(--red); }

    @media (max-width: 720px) {
      header { flex-direction: column; align-items: flex-start; }
      .status-pill { align-self: flex-start; }
      body { padding: 18px; }
      .grid { padding: 0 18px 18px 18px; }
      .note { padding: 0 18px 16px 18px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div>
        <div class="title"><span class="dot"></span>GME NetPulse</div>
        <div class="meta">Live LAN/internet status, refreshed automatically</div>
      </div>
      <div class="status-pill" id="internet-pill">
        <span class="status-dot" id="internet-dot"></span>
        <span id="internet-text">checking...</span>
      </div>
    </header>
    <div class="note" id="updated-at">Last updated: -</div>
    <div class="grid" id="cards"></div>
    <div class="note">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  </div>

  <script>
    const colors = {
      online: '#4ade80',
      offline: '#f8c343',
      disconnected: '#ff6b6b'
    };

    async function fetchStatus() {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error('Status fetch failed');
      return res.json();
    }

    function stateLabel(state) {
      if (state === 'online') return 'Online';
      if (state === 'offline') return 'Offline';
      return 'Disconnected';
    }

    function render(data) {
      const pill = document.getElementById('internet-pill');
      const dot = document.getElementById('internet-dot');
      const text = document.getElementById('internet-text');
      const updated = document.getElementById('updated-at');
      const cards = document.getElementById('cards');

      const inetState = data.internet.state || 'offline';
      dot.style.background = colors[inetState];
      dot.style.boxShadow = `0 0 14px ${colors[inetState]}`;
      text.textContent = inetState === 'online' ? 'Internet reachable' : 'No internet';

      updated.textContent = `Last updated: ${data.timestamp}`;

      cards.innerHTML = '';
      data.adapters.forEach((ad) => {
        const barClass = ad.state === 'disconnected' ? 'disconnected' : (ad.state === 'offline' ? 'offline' : '');

        const card = document.createElement('div');
        card.className = 'card';
        const ips = (ad.ips || []).join(', ');
        card.innerHTML = `
          <div class="bar ${barClass}" style="background:${colors[ad.state]};"></div>
          <div class="card-header">
            <h3>${ad.name}</h3>
            <div class="badge">${stateLabel(ad.state)}</div>
          </div>
          <div class="desc">${ad.description || '-'}</div>
          <div class="row">
            <span class="pill">${ad.status}</span>
            <span class="pill">${ad.link_speed || 'Speed N/A'}</span>
            <span class="pill">MAC ${ad.mac || '-'}</span>
          </div>
          <div class="row" style="margin-top:10px;">
            <span class="pill">Admin: ${ad.admin_status}</span>
            <span class="pill">IP: ${ips || 'n/a'}</span>
          </div>
        `;
        cards.appendChild(card);
      });
    }

    async function loop() {
      try {
        const data = await fetchStatus();
        render(data);
      } catch (err) {
        console.error(err);
      } finally {
        setTimeout(loop, 3000);
      }
    }

    loop();
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _set_common_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._set_common_headers(content_type="text/html; charset=utf-8")
            self.wfile.write(HTML.encode("utf-8"))
            return

        if parsed.path == "/api/status":
            status_payload = build_status()
            self._set_common_headers(content_type="application/json")
            self.wfile.write(json.dumps(status_payload).encode("utf-8"))
            return

        if parsed.path == "/favicon.ico":
            # Return a tiny inline SVG favicon with DG initials.
            favicon_svg = (
                "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
                "<rect width='64' height='64' rx='12' fill='#0f1629'/>"
                "<rect x='6' y='6' width='52' height='52' rx='10' fill='#6ae6ff'/>"
                "<text x='50%' y='58%' text-anchor='middle' font-family='Segoe UI, Arial' font-size='26' font-weight='700' fill='#0f1629'>DG</text>"
                "</svg>"
            )
            self._set_common_headers(content_type="image/svg+xml")
            self.wfile.write(favicon_svg.encode("utf-8"))
            return

        self._set_common_headers(status=404)
        self.wfile.write(b"Not found")


def main():
    parser = argparse.ArgumentParser(description="GME NetPulse")
    parser.add_argument("--port", type=int, help="HTTP port to listen on", default=1989)
    parser.add_argument("--host", default="0.0.0.0", help="Host/IP to bind (default 0.0.0.0)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    def choose_port(default_port: int, prompt: bool, arg_port: int) -> int:
        if arg_port and 1 <= arg_port <= 65535:
            return arg_port
        if not prompt:
            return default_port
        try:
            user = input(f"Enter HTTP port [{default_port}]: ").strip()
            if user:
                val = int(user)
                if 1 <= val <= 65535:
                    return val
        except Exception:
            pass
        return default_port

    port = choose_port(1989, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host
    server = HTTPServer((host, port), Handler)
    print(f"GME NetPulse running on http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    minimize_console()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
