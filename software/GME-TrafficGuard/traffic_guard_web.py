#!/usr/bin/env python3
"""
GME TrafficGuard Web
Lightweight HTTP server + web UI for PCAP usage analysis with XLSX export.
Pure stdlib; no external deps.
"""

import argparse
import cgi
import io
import json
import os
import socket
import struct
import tempfile
import threading
import time
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import BinaryIO, DefaultDict, Dict, List, Optional, Set, Tuple

# --------------- PCAP parsing (from desktop analyzer) ---------------

PCAP_MAGIC_USEC_BE = 0xA1B2C3D4
PCAP_MAGIC_USEC_LE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_BE = 0xA1B23C4D
PCAP_MAGIC_NSEC_LE = 0x4D3CB2A1
DLT_EN10MB = 1  # Ethernet


class PcapHeader:
    def __init__(self, endian: str, snaplen: int, network: int):
        self.endian = endian
        self.snaplen = snaplen
        self.network = network


def read_pcap_global_header(f: BinaryIO) -> PcapHeader:
    data = f.read(24)
    if len(data) != 24:
        raise ValueError("Not a valid pcap file (short global header)")
    magic_bytes = data[:4]
    if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported or corrupt pcap magic number")
    _, _, _, _, snaplen, network = struct.unpack(endian + "HHIIII", data[4:])
    return PcapHeader(endian=endian, snaplen=snaplen, network=network)


def iter_pcap_packets(f: BinaryIO, header: PcapHeader):
    ph_struct = struct.Struct(header.endian + "IIII")
    while True:
        hdr = f.read(ph_struct.size)
        if not hdr or len(hdr) != ph_struct.size:
            break
        ts_sec, ts_usec, incl_len, orig_len = ph_struct.unpack(hdr)
        data = f.read(incl_len)
        if len(data) != incl_len:
            break
        yield (ts_sec, ts_usec, incl_len, orig_len, data)


def parse_ipv4(pkt: bytes, offset: int) -> Optional[Tuple[str, str, int]]:
    if len(pkt) < offset + 20:
        return None
    first = pkt[offset]
    version = first >> 4
    ihl = first & 0x0F
    if version != 4 or ihl < 5:
        return None
    total_length = struct.unpack("!H", pkt[offset + 2 : offset + 4])[0]
    src = pkt[offset + 12 : offset + 16]
    dst = pkt[offset + 16 : offset + 20]
    src_ip = ".".join(str(b) for b in src)
    dst_ip = ".".join(str(b) for b in dst)
    return (src_ip, dst_ip, int(total_length))


def parse_ipv6(pkt: bytes, offset: int) -> Optional[Tuple[str, str, int]]:
    if len(pkt) < offset + 40:
        return None
    version = pkt[offset] >> 4
    if version != 6:
        return None
    payload_len = struct.unpack("!H", pkt[offset + 4 : offset + 6])[0]
    total_length = 40 + int(payload_len)
    src = pkt[offset + 8 : offset + 24]
    dst = pkt[offset + 24 : offset + 40]

    def ipv6_to_str(b: bytes) -> str:
        groups = struct.unpack("!8H", b)
        best_start = -1
        best_len = 0
        cur_start = -1
        cur_len = 0
        for i, g in enumerate(groups + (1,)):
            if i < 8 and g == 0:
                if cur_start == -1:
                    cur_start = i
                    cur_len = 1
                else:
                    cur_len += 1
            else:
                if cur_start != -1 and cur_len > best_len:
                    best_start, best_len = cur_start, cur_len
                cur_start, cur_len = -1, 0
        parts = []
        i = 0
        while i < 8:
            if best_len > 1 and i == best_start:
                parts.append("")
                i += best_len
                if i == 8:
                    parts.append("")
                continue
            parts.append(f"{groups[i]:x}")
            i += 1
        return ":".join(parts)

    return (ipv6_to_str(src), ipv6_to_str(dst), int(total_length))


class IpStats:
    def __init__(self):
        self.bytes_total = 0
        self.packets_total = 0
        self.bytes_src = 0
        self.packets_src = 0
        self.bytes_dst = 0
        self.packets_dst = 0


def analyze_pcap(
    path: str,
    router_ip: Optional[str] = None,
    internet_only: bool = False,
    allow_ipv6: bool = True,
) -> Tuple[Dict[str, IpStats], float, Dict[str, Dict[str, int]], Dict[str, Dict[str, int]]]:
    with open(path, "rb") as f:
        gh = read_pcap_global_header(f)
        linktype = gh.network
        stats: Dict[str, IpStats] = {}
        peer_out: DefaultDict[str, Dict[str, int]] = DefaultDict(lambda: DefaultDict(int))
        peer_in: DefaultDict[str, Dict[str, int]] = DefaultDict(lambda: DefaultDict(int))
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None
        for ts_sec, ts_usec, _incl_len, _orig_len, data in iter_pcap_packets(f, gh):
            ts = float(ts_sec) + (float(ts_usec) / 1_000_000.0)
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            ip_info: Optional[Tuple[str, str, int]] = None
            if linktype == DLT_EN10MB:
                if len(data) < 14:
                    continue
                eth_type = struct.unpack("!H", data[12:14])[0]
                if eth_type == 0x0800:
                    ip_info = parse_ipv4(data, 14)
                elif eth_type == 0x86DD and allow_ipv6:
                    ip_info = parse_ipv6(data, 14)
            elif linktype == 276:
                if len(data) < 21:
                    continue
                ipver = data[20] >> 4
                if ipver == 4:
                    ip_info = parse_ipv4(data, 20)
                elif ipver == 6 and allow_ipv6:
                    ip_info = parse_ipv6(data, 20)
            else:
                continue
            if not ip_info:
                continue
            src_ip, dst_ip, ip_len = ip_info

            s = stats.setdefault(src_ip, IpStats())
            d = stats.setdefault(dst_ip, IpStats())

            if router_ip:
                if src_ip == router_ip and dst_ip != router_ip:
                    d.bytes_total += ip_len
                    d.packets_total += 1
                    d.bytes_dst += ip_len
                    d.packets_dst += 1
                    peer_in[dst_ip][src_ip] = peer_in[dst_ip].get(src_ip, 0) + ip_len
                elif dst_ip == router_ip and src_ip != router_ip:
                    s.bytes_total += ip_len
                    s.packets_total += 1
                    s.bytes_src += ip_len
                    s.packets_src += 1
                    peer_out[src_ip][dst_ip] = peer_out[src_ip].get(dst_ip, 0) + ip_len
            elif internet_only:
                try:
                    src_priv = is_private_ip(src_ip)
                    dst_priv = is_private_ip(dst_ip)
                except Exception:
                    continue
                dev_ip = None
                ext_ip = None
                if src_priv and not dst_priv:
                    dev_ip, ext_ip = src_ip, dst_ip
                    s.bytes_total += ip_len
                    s.packets_total += 1
                    s.bytes_src += ip_len
                    s.packets_src += 1
                elif dst_priv and not src_priv:
                    dev_ip, ext_ip = dst_ip, src_ip
                    d.bytes_total += ip_len
                    d.packets_total += 1
                    d.bytes_dst += ip_len
                    d.packets_dst += 1
                if dev_ip and ext_ip:
                    if dev_ip == src_ip:
                        peer_out[dev_ip][ext_ip] = peer_out[dev_ip].get(ext_ip, 0) + ip_len
                    else:
                        peer_in[dev_ip][ext_ip] = peer_in[dev_ip].get(ext_ip, 0) + ip_len
            else:
                s.bytes_total += ip_len
                s.packets_total += 1
                s.bytes_src += ip_len
                s.packets_src += 1
                d.bytes_total += ip_len
                d.packets_total += 1
                d.bytes_dst += ip_len
                d.packets_dst += 1

        duration = 0.0
        if first_ts is not None and last_ts is not None:
            duration = max(0.0, last_ts - first_ts)
        return stats, duration, peer_out, peer_in


def is_private_ip(ip_str: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("fc00::/7"):
        return True
    return False


def export_xlsx(rows: List[Tuple], out_path: str) -> None:
    content_types = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        b'<Default Extension="xml" ContentType="application/xml"/>'
        b'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        b'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        b'<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        b"</Types>"
    )
    rels = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        b"</Relationships>"
    )
    wb = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        b'<sheets><sheet name="Usage" sheetId="1" r:id="rId1"/></sheets>'
        b"</workbook>"
    )
    wb_rels = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        b"</Relationships>"
    )
    styles = b'<?xml version="1.0" encoding="UTF-8"?>' b'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"></styleSheet>'

    headers = [
        "Rank",
        "Name",
        "IP",
        "Top Out Dest",
        "Top In Source",
        "Avg MB/s",
        "MB/hour",
        "MB/month",
    ]

    def col_letter(n: int) -> str:
        s = ""
        while n:
            n, r = divmod(n - 1, 26)
            s = chr(65 + r) + s
        return s

    def cell(r: int, c: int, v: str, t: str = "str") -> str:
        addr = f"{col_letter(c)}{r}"
        if t == "n":
            return f'<c r="{addr}"><v>{v}</v></c>'
        else:
            return f'<c r="{addr}" t="inlineStr"><is><t>{v}</t></is></c>'

    sheet_rows = []
    r_idx = 1
    row_xml = "".join(cell(r_idx, i + 1, headers[i]) for i in range(len(headers)))
    sheet_rows.append(f'<row r="{r_idx}">{row_xml}</row>')
    for i, row in enumerate(rows, start=1):
        r_idx = i + 1
        rank, name, ip, top_out_peer, top_in_peer, avg_mbps, mb_hour, mb_month = row
        row_xml = "".join(
            [
                cell(r_idx, 1, str(rank), "n"),
                cell(r_idx, 2, name or "", "str"),
                cell(r_idx, 3, ip, "str"),
                cell(r_idx, 4, top_out_peer or "", "str"),
                cell(r_idx, 5, top_in_peer or "", "str"),
                cell(r_idx, 6, f"{avg_mbps:.6f}", "n"),
                cell(r_idx, 7, f"{mb_hour:.3f}", "n"),
                cell(r_idx, 8, f"{mb_month:.3f}", "n"),
            ]
        )
        sheet_rows.append(f'<row r="{r_idx}">{row_xml}</row>')

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{''.join(sheet_rows)}</sheetData>"
        "</worksheet>"
    ).encode("utf-8")

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", styles)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)


# --------------- HTTP server + state ---------------

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8095
state_lock = threading.Lock()
last_result: Dict = {}
last_rows: List[Tuple] = []
last_filename: str = ""


def format_summary(stats: Dict[str, IpStats], duration: float, peer_out: Dict, peer_in: Dict) -> List[Dict]:
    MB = 1_000_000.0
    items = []
    for ip, s in stats.items():
        avg_mb_s = (s.bytes_total / MB / duration) if duration > 0 else 0.0
        mb_hour = avg_mb_s * 3600.0
        mb_month = avg_mb_s * (30.0 * 86400.0)
        top_out = ""
        top_in = ""
        if ip in peer_out and peer_out[ip]:
            top_out = max(peer_out[ip].items(), key=lambda kv: kv[1])[0]
        if ip in peer_in and peer_in[ip]:
            top_in = max(peer_in[ip].items(), key=lambda kv: kv[1])[0]
        items.append(
            {
                "ip": ip,
                "total_mb": s.bytes_total / MB,
                "avg_mb_s": avg_mb_s,
                "mb_hour": mb_hour,
                "mb_month": mb_month,
                "top_out": top_out,
                "top_in": top_in,
            }
        )
    items.sort(key=lambda x: x["total_mb"], reverse=True)
    return items


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, code: int, payload: Dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            body = INDEX_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/last":
            with state_lock:
                payload = {"result": last_result, "filename": last_filename}
            self._send_json(200, payload)
            return
        if self.path.startswith("/api/export"):
            with state_lock:
                rows = list(last_rows)
            if not rows:
                self._send_json(400, {"error": "No data to export"})
                return
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
            tmp.close()
            export_xlsx(rows, tmp.name)
            data = open(tmp.name, "rb").read()
            os.unlink(tmp.name)
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            self.send_header("Content-Disposition", 'attachment; filename="gme-trafficguard.xlsx"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/api/upload"):
            ctype, pdict = cgi.parse_header(self.headers.get("Content-Type", ""))
            if ctype != "multipart/form-data":
                self._send_json(400, {"error": "multipart/form-data required"})
                return
            pdict["boundary"] = pdict["boundary"].encode("utf-8")
            pdict["CONTENT-LENGTH"] = int(self.headers.get("Content-Length", "0"))
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST"})
            fileitem = form["pcap"] if "pcap" in form else None
            router_ip = form["router"].value if "router" in form and form["router"].value else None
            internet_only = form["internet_only"].value == "true" if "internet_only" in form else False
            allow_ipv6 = form["allow_ipv6"].value != "false" if "allow_ipv6" in form else True
            if not fileitem or not fileitem.file:
                self._send_json(400, {"error": "pcap field required"})
                return
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(fileitem.file.read())
                tmp_path = tmp.name
            try:
                stats, duration, peer_out, peer_in = analyze_pcap(tmp_path, router_ip, internet_only, allow_ipv6)
                items = format_summary(stats, duration, peer_out, peer_in)
                rows = [
                    (
                        idx + 1,
                        "",
                        item["ip"],
                        item["top_out"],
                        item["top_in"],
                        item["avg_mb_s"],
                        item["mb_hour"],
                        item["mb_month"],
                    )
                    for idx, item in enumerate(items)
                ]
                with state_lock:
                    global last_result, last_rows, last_filename
                    last_result = {"items": items, "duration": duration, "count": len(items)}
                    last_rows = rows
                    last_filename = os.path.basename(fileitem.filename or "upload.pcap")
                self._send_json(200, {"ok": True, "result": last_result, "filename": last_filename})
            except Exception as exc:  # noqa: BLE001
                self._send_json(400, {"error": str(exc)})
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            return
        self._send_json(404, {"error": "not found"})


def get_local_ips() -> List[str]:
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addr = info[4][0]
            if ":" in addr or addr.startswith("127."):
                continue
            if addr not in ips:
                ips.append(addr)
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return ips


def choose_port(default_port: int, prompt: bool, arg_port: Optional[int]) -> int:
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


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GME TrafficGuard (Web)</title>
  <style>
    body { font-family: "Segoe UI", system-ui, sans-serif; margin:0; padding:16px; background:#0f172a; color:#e5e7eb; }
    h1 { margin:0 0 12px; }
    .card { background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1); border-radius:10px; padding:14px; }
    label { display:block; margin-top:8px; font-size:13px; color:#cbd5e1; }
    input[type=file], input[type=text] { width:100%; margin-top:4px; }
    button { margin-top:12px; padding:10px 12px; border:0; border-radius:8px; background:#38bdf8; color:#04101f; font-weight:700; cursor:pointer; }
    table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
    th, td { padding:8px; border-bottom:1px solid rgba(255,255,255,0.08); text-align:left; }
    th { color:#94a3b8; font-size:11px; letter-spacing:0.3px; text-transform:uppercase; }
    .muted { color:#94a3b8; font-size:12px; }
    .footer { margin-top:12px; color:#94a3b8; font-size:12px; }
  </style>
</head>
<body>
  <h1>GME TrafficGuard (Web)</h1>
  <div class="card">
    <form id="uploadForm">
      <label>PCAP file</label>
      <input type="file" name="pcap" required />
      <label>Router IP (optional, to include only device↔router)</label>
      <input type="text" name="router" placeholder="192.168.0.1" />
      <label><input type="checkbox" name="internet_only" /> Internet-only (private ↔ public)</label>
      <label><input type="checkbox" name="allow_ipv6" checked /> Allow IPv6</label>
      <button type="submit">Analyze</button>
    </form>
    <div id="status" class="muted" style="margin-top:8px;">Idle</div>
    <div style="margin-top:12px;">
      <button onclick="exportXlsx()">Export XLSX</button>
      <span class="muted" id="filename"></span>
    </div>
    <table id="results" style="display:none;">
      <thead><tr><th>#</th><th>IP</th><th>Total MB</th><th>Avg MB/s</th><th>MB/hour</th><th>MB/month</th><th>Top Out</th><th>Top In</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>
  <div class="footer">Designed and built by Dan Gibson &amp; Codex 2025 (Gibson Marine Electrical LTD)</div>
  <script>
    async function analyze(e){
      e.preventDefault();
      const form = document.getElementById('uploadForm');
      const data = new FormData(form);
      document.getElementById('status').textContent='Parsing...';
      const res = await fetch('/api/upload',{method:'POST',body:data});
      const j = await res.json();
      if(!res.ok){ document.getElementById('status').textContent='Error: '+(j.error||res.statusText); return;}
      document.getElementById('status').textContent='Parsed '+(j.result.count||0)+' devices; duration '+j.result.duration.toFixed(1)+'s';
      document.getElementById('filename').textContent = j.filename ? ('Last file: '+j.filename) : '';
      const tbody = document.querySelector('#results tbody');
      tbody.innerHTML='';
      (j.result.items||[]).forEach((it,idx)=>{
        const tr=document.createElement('tr');
        tr.innerHTML = `<td>${idx+1}</td><td>${it.ip}</td><td>${it.total_mb.toFixed(3)}</td><td>${it.avg_mb_s.toFixed(6)}</td><td>${it.mb_hour.toFixed(3)}</td><td>${it.mb_month.toFixed(3)}</td><td>${it.top_out||''}</td><td>${it.top_in||''}</td>`;
        tbody.appendChild(tr);
      });
      document.getElementById('results').style.display = 'table';
    }
    document.getElementById('uploadForm').addEventListener('submit', analyze);
    async function exportXlsx(){
      const res = await fetch('/api/export');
      if(!res.ok){ const j=await res.json(); alert(j.error||'Export failed'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'gme-trafficguard.xlsx'; a.click();
      URL.revokeObjectURL(url);
    }
  </script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="GME TrafficGuard Web")
    parser.add_argument("--port", type=int, help="HTTP port to listen on")
    parser.add_argument("--host", default=SERVER_HOST, help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--no-prompt", action="store_true", help="Do not prompt for port; use defaults/args")
    args = parser.parse_args()

    port = choose_port(SERVER_PORT, prompt=not args.no_prompt, arg_port=args.port)
    host = args.host

    server = HTTPServer((host, port), Handler)
    print(f"GME TrafficGuard Web running on http://{host}:{port}")
    ips = get_local_ips()
    if ips:
        print("Also reachable (LAN): " + " ".join(f"http://{ip}:{port}" for ip in ips))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
