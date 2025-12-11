#!/usr/bin/env python3
"""
Portable PCAP usage analyzer

Features:
- Parses .pcap files (DLT_EN10MB/Ethernet) without third-party libraries
- Aggregates bytes per IP (v4 + v6), counts packets, bytes as source/dest
- Tkinter GUI to pick a PCAP, view sorted results, and export to XLSX
- XLSX export implemented via zipfile + minimal XML (no external deps)

Limitations:
- Only supports classic PCAP (not PCAP-NG)
- Only supports Ethernet link layer (DLT_EN10MB = 1)
"""

import os
import struct
import threading
import subprocess
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Tuple, BinaryIO, Optional, List, DefaultDict, Set
import ipaddress
import urllib.request

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tkfont
import zipfile
import io
import math


# -------------------------
# PCAP parsing primitives
# -------------------------

PCAP_MAGIC_USEC_BE = 0xA1B2C3D4
PCAP_MAGIC_USEC_LE = 0xD4C3B2A1
PCAP_MAGIC_NSEC_BE = 0xA1B23C4D
PCAP_MAGIC_NSEC_LE = 0x4D3CB2A1

DLT_EN10MB = 1  # Ethernet


@dataclass
class PcapHeader:
    endian: str  # '>' or '<'
    snaplen: int
    network: int


def read_pcap_global_header(f: BinaryIO) -> PcapHeader:
    data = f.read(24)
    if len(data) != 24:
        raise ValueError("Not a valid pcap file (short global header)")
    magic_bytes = data[:4]

    if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):  # LE usec/nsec
        endian = '<'
    elif magic_bytes in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):  # BE usec/nsec
        endian = '>'
    else:
        raise ValueError("Unsupported or corrupt pcap magic number")

    # version_major, version_minor, thiszone, sigfigs, snaplen, network
    _, _, _, _, snaplen, network = struct.unpack(endian + 'HHIIII', data[4:])
    return PcapHeader(endian=endian, snaplen=snaplen, network=network)


def iter_pcap_packets(f: BinaryIO, header: PcapHeader):
    ph_struct = struct.Struct(header.endian + 'IIII')
    while True:
        hdr = f.read(ph_struct.size)
        if not hdr:
            break
        if len(hdr) != ph_struct.size:
            # Truncated file; stop cleanly
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
    total_length = struct.unpack('!H', pkt[offset+2:offset+4])[0]
    src = pkt[offset+12:offset+16]
    dst = pkt[offset+16:offset+20]
    src_ip = '.'.join(str(b) for b in src)
    dst_ip = '.'.join(str(b) for b in dst)
    return (src_ip, dst_ip, int(total_length))


def parse_ipv6(pkt: bytes, offset: int) -> Optional[Tuple[str, str, int]]:
    if len(pkt) < offset + 40:
        return None
    version = pkt[offset] >> 4
    if version != 6:
        return None
    payload_len = struct.unpack('!H', pkt[offset+4:offset+6])[0]
    total_length = 40 + int(payload_len)
    src = pkt[offset+8:offset+24]
    dst = pkt[offset+24:offset+40]

    def ipv6_to_str(b: bytes) -> str:
        groups = struct.unpack('!8H', b)
        # Compress longest run of zeros
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
                parts.append('')
                i += best_len
                if i == 8:
                    parts.append('')
                continue
            parts.append(f"{groups[i]:x}")
            i += 1
        return ':'.join(parts)

    return (ipv6_to_str(src), ipv6_to_str(dst), int(total_length))


@dataclass
class IpStats:
    bytes_total: int = 0
    packets_total: int = 0
    bytes_src: int = 0
    packets_src: int = 0
    bytes_dst: int = 0
    packets_dst: int = 0


def analyze_pcap(path: str, router_ip: Optional[str] = None, internet_only: bool = False, allow_ipv6: bool = True) -> Tuple[Dict[str, IpStats], float, Dict[str, Dict[str, int]], Dict[str, Dict[str, int]]]:
    with open(path, 'rb') as f:
        gh = read_pcap_global_header(f)
        linktype = gh.network
        stats: Dict[str, IpStats] = defaultdict(IpStats)
        peer_out: DefaultDict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        peer_in: DefaultDict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None
        for ts_sec, ts_usec, _incl_len, _orig_len, data in iter_pcap_packets(f, gh):
            ts = float(ts_sec) + (float(ts_usec) / (1_000_000.0))
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            ip_info: Optional[Tuple[str, str, int]] = None
            if linktype == DLT_EN10MB:
                if len(data) < 14:
                    continue
                eth_type = struct.unpack('!H', data[12:14])[0]
                if eth_type == 0x0800:  # IPv4
                    ip_info = parse_ipv4(data, 14)
                elif eth_type == 0x86DD and allow_ipv6:  # IPv6
                    ip_info = parse_ipv6(data, 14)
            elif linktype == 276:
                # LINKTYPE_NG40 (20-byte pseudo header), IP header starts at +20
                if len(data) < 21:
                    continue
                ipver = data[20] >> 4
                if ipver == 4:
                    ip_info = parse_ipv4(data, 20)
                elif ipver == 6 and allow_ipv6:
                    ip_info = parse_ipv6(data, 20)
            else:
                # Unsupported link type; skip packet
                continue
            if not ip_info:
                continue
            src_ip, dst_ip, ip_len = ip_info

            if router_ip:
                # Only count traffic where one side is the router IP
                if src_ip == router_ip and dst_ip != router_ip:
                    dev_ip = dst_ip
                    d = stats[dev_ip]
                    d.bytes_total += ip_len
                    d.packets_total += 1
                    d.bytes_dst += ip_len  # inbound to device from router
                    d.packets_dst += 1
                    # inbound to device from router
                    peer_in[dev_ip][src_ip] = peer_in[dev_ip].get(src_ip, 0) + ip_len
                elif dst_ip == router_ip and src_ip != router_ip:
                    dev_ip = src_ip
                    s = stats[dev_ip]
                    s.bytes_total += ip_len
                    s.packets_total += 1
                    s.bytes_src += ip_len  # outbound from device to router
                    s.packets_src += 1
                    # outbound from device to router
                    peer_out[dev_ip][dst_ip] = peer_out[dev_ip].get(dst_ip, 0) + ip_len
                else:
                    # Not router-related; skip
                    continue
            elif internet_only:
                # Count only device (private) <-> public traffic; attribute to device IP
                try:
                    src_priv = is_private_ip(src_ip)
                    dst_priv = is_private_ip(dst_ip)
                except Exception:
                    continue
                dev_ip: Optional[str] = None
                ext_ip: Optional[str] = None
                if src_priv and not dst_priv:
                    dev_ip, ext_ip = src_ip, dst_ip
                    s = stats[dev_ip]
                    s.bytes_total += ip_len
                    s.packets_total += 1
                    s.bytes_src += ip_len
                    s.packets_src += 1
                elif dst_priv and not src_priv:
                    dev_ip, ext_ip = dst_ip, src_ip
                    d = stats[dev_ip]
                    d.bytes_total += ip_len
                    d.packets_total += 1
                    d.bytes_dst += ip_len
                    d.packets_dst += 1
                else:
                    continue
                if dev_ip and ext_ip:
                    if dev_ip == src_ip:
                        peer_out[dev_ip][ext_ip] = peer_out[dev_ip].get(ext_ip, 0) + ip_len
                    else:
                        peer_in[dev_ip][ext_ip] = peer_in[dev_ip].get(ext_ip, 0) + ip_len
            else:
                # Update per-IP totals (count both src and dst towards total usage)
                s = stats[src_ip]
                s.bytes_total += ip_len
                s.packets_total += 1
                s.bytes_src += ip_len
                s.packets_src += 1
                d = stats[dst_ip]
                d.bytes_total += ip_len
                d.packets_total += 1
                d.bytes_dst += ip_len
                d.packets_dst += 1
                # Track private <-> public peers directionally
                try:
                    src_priv = is_private_ip(src_ip)
                    dst_priv = is_private_ip(dst_ip)
                except Exception:
                    src_priv = dst_priv = False
                if src_priv and not dst_priv:
                    peer_out[src_ip][dst_ip] = peer_out[src_ip].get(dst_ip, 0) + ip_len
                if dst_priv and not src_priv:
                    peer_in[dst_ip][src_ip] = peer_in[dst_ip].get(src_ip, 0) + ip_len

        duration = 0.0
        if first_ts is not None and last_ts is not None:
            duration = max(0.0, last_ts - first_ts)
        return stats, duration, peer_out, peer_in


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network('fc00::/7'):
        return True
    return False


# -------------------------
# Network enrichment helpers
# -------------------------

def nslookup_host(ip: str, dns_server: str = '8.8.8.8', timeout: float = 2.0) -> Optional[str]:
    """
    Resolve an IP using nslookup pointing at a specific DNS server.
    Returns the hostname (stripped / lower-cased) or None if not found.
    """
    try:
        run_kwargs = dict(capture_output=True, text=True, timeout=timeout)
        if os.name == 'nt':
            # Hide console flashes on Windows
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            run_kwargs['startupinfo'] = si
            run_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        res = subprocess.run(['nslookup', ip, dns_server], **run_kwargs)
    except Exception:
        return None
    output = (res.stdout or '') + (res.stderr or '')
    host = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if 'name =' in line.lower():
            # nslookup format: Name: something or name = something
            host = line.split('=', 1)[-1].strip().rstrip('.')
            break
        if line.lower().startswith('name:'):
            host = line.split(':', 1)[-1].strip().rstrip('.')
            break
    if host:
        return host.lower()
    return None


def lookup_country_http(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Query ip-api.com for a country code; returns ISO2 or None."""
    if is_private_ip(ip):
        return None
    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,message"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='ignore'))
    except Exception:
        return None
    if data.get('status') == 'success':
        cc = data.get('countryCode')
        if cc:
            return cc.upper()
    return None


def guess_provider(host_or_ip: str) -> Optional[str]:
    """
    Best-effort provider hint based on hostname substrings or well-known IPs.
    Not authoritative; purely heuristic.
    """
    s = host_or_ip.lower()
    try:
        ip_obj = ipaddress.ip_address(host_or_ip)
    except Exception:
        ip_obj = None

    # IP-based quick hits
    ip_hits = {
        '8.8.8.8': 'Google DNS',
        '8.8.4.4': 'Google DNS',
        '1.1.1.1': 'Cloudflare',
        '1.0.0.1': 'Cloudflare',
        '9.9.9.9': 'Quad9',
        '149.112.112.112': 'Quad9',
        '208.67.222.222': 'Cisco/OpenDNS',
        '208.67.220.220': 'Cisco/OpenDNS',
    }
    if ip_obj and host_or_ip in ip_hits:
        return ip_hits[host_or_ip]

    checks = [
        (('google', '1e100', 'gstatic', 'googleapis', 'dns.google'), 'Google'),
        (('amazonaws', 'cloudfront', 'aws', '.amazon.'), 'AWS/Amazon'),
        (('cloudflare', 'cloudflareresolve'), 'Cloudflare'),
        (('quad9',), 'Quad9'),
        (('opendns', 'cisco'), 'Cisco/OpenDNS'),
        (('microsoft', 'windows', 'office', 'live.com', 'onedrive', 'azure'), 'Microsoft'),
        (('fbcdn', 'facebook', 'meta'), 'Meta/Facebook'),
        (('netflix', 'nflx'), 'Netflix'),
        (('apple', 'icloud'), 'Apple'),
    ]
    for substrs, label in checks:
        if any(sub in s for sub in substrs):
            return label
    return None


# -------------------------
# XLSX minimal writer
# -------------------------

def export_xlsx(rows: List[Tuple], out_path: str) -> None:
    """
    Write rows to an .xlsx workbook with a single sheet.
    rows: list of (rank, name, provider, ip, top_out_peer, top_in_peer, avg_mb_s, mb_hour, mb_month, flag)
    """
    # Build XML parts
    content_types = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        b"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        b"<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        b"<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        b"<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
        b"<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
        b"<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>"
        b"</Types>"
    )
    rels = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        b"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>"
        b"</Relationships>"
    )
    wb = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        b"<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
        b"<sheets><sheet name=\"Usage\" sheetId=\"1\" r:id=\"rId1\"/></sheets>"
        b"</workbook>"
    )
    wb_rels = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        b"<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        b"<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/>"
        b"</Relationships>"
    )
    styles = (
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        b"<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        b"</styleSheet>"
    )

    # Build sheet XML with header row + data rows
    headers = [
        "Rank", "Name", "Provider", "IP", "Top Out Dest", "Top In Source", "Avg MB/s", "MB/hour", "MB/month", "Flag"
    ]
    # Convert a column number (1-based) to Excel column letters
    def col_letter(n: int) -> str:
        s = ''
        while n:
            n, r = divmod(n - 1, 26)
            s = chr(65 + r) + s
        return s

    def cell(r: int, c: int, v: str, t: str = 'str') -> str:
        addr = f"{col_letter(c)}{r}"
        if t == 'n':
            return f"<c r=\"{addr}\"><v>{v}</v></c>"
        else:
            return f"<c r=\"{addr}\" t=\"inlineStr\"><is><t>{v}</t></is></c>"

    sheet_rows = []
    # Header row
    r_idx = 1
    row_xml = ''.join(cell(r_idx, i+1, headers[i]) for i in range(len(headers)))
    sheet_rows.append(f"<row r=\"{r_idx}\">{row_xml}</row>")
    # Data rows
    for i, row in enumerate(rows, start=1):
        r_idx = i + 1
        # Expect row format to match headers order
        rank, name, provider, ip, top_out_peer, top_in_peer, avg_mbps, mb_hour, mb_month, flag = row
        row_xml = ''.join([
            cell(r_idx, 1, str(rank), 'n'),
            cell(r_idx, 2, name or '', 'str'),
            cell(r_idx, 3, provider or '', 'str'),
            cell(r_idx, 4, ip, 'str'),
            cell(r_idx, 5, top_out_peer or '', 'str'),
            cell(r_idx, 6, top_in_peer or '', 'str'),
            cell(r_idx, 7, f"{avg_mbps:.6f}", 'n'),
            cell(r_idx, 8, f"{mb_hour:.3f}", 'n'),
            cell(r_idx, 9, f"{mb_month:.3f}", 'n'),
            cell(r_idx, 10, flag, 'str'),
        ])
        sheet_rows.append(f"<row r=\"{r_idx}\">{row_xml}</row>")

    sheet_xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        f"<sheetData>{''.join(sheet_rows)}</sheetData>"
        "</worksheet>"
    ).encode('utf-8')

    # Write zip
    with zipfile.ZipFile(out_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types)
        z.writestr('_rels/.rels', rels)
        z.writestr('xl/workbook.xml', wb)
        z.writestr('xl/_rels/workbook.xml.rels', wb_rels)
        z.writestr('xl/styles.xml', styles)
        z.writestr('xl/worksheets/sheet1.xml', sheet_xml)


# -------------------------
# GUI
# -------------------------

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title('GME TrafficGuard (PCAP Usage)')
        self.geometry('900x500')
        self.minsize(800, 400)
        self._stats: Dict[str, IpStats] = {}
        self._pcap_path: Optional[str] = None

        # Menu bar with About
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label='About…', command=self.show_about)
        menubar.add_cascade(label='Help', menu=helpmenu)
        self.config(menu=menubar)

        # Top frame with buttons
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=8)
        self.open_btn = ttk.Button(top, text='Open PCAP…', command=self.open_pcap)
        self.open_btn.pack(side=tk.LEFT)
        self.refresh_btn = ttk.Button(top, text='Refresh', command=self.refresh_analysis, state=tk.DISABLED)
        self.refresh_btn.pack(side=tk.LEFT, padx=(8,0))
        self.export_btn = ttk.Button(top, text='Export XLSX…', command=self.export_xlsx_action, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=(8,0))
        self.status_var = tk.StringVar(value='Ready')
        self.status_lbl = ttk.Label(top, textvariable=self.status_var)
        self.status_lbl.pack(side=tk.RIGHT)

        # Filters and options
        opts = ttk.Frame(self)
        opts.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,8))
        ttk.Label(opts, text='Router IP:').pack(side=tk.LEFT)
        self.router_var = tk.StringVar()
        self.router_entry = ttk.Entry(opts, textvariable=self.router_var, width=18)
        self.router_entry.pack(side=tk.LEFT, padx=(4,12))
        self.internet_var = tk.BooleanVar(value=True)
        self.internet_chk = ttk.Checkbutton(opts, text='Internet only (exclude LAN-LAN)', variable=self.internet_var)
        self.internet_chk.pack(side=tk.LEFT, padx=(0,8))
        self.resolve_dns_var = tk.BooleanVar(value=True)
        self.resolve_chk = ttk.Checkbutton(opts, text='Resolve names (8.8.8.8)', variable=self.resolve_dns_var, command=self.refresh_analysis)
        self.resolve_chk.pack(side=tk.LEFT, padx=(0,8))
        self.ipv6_var = tk.BooleanVar(value=True)
        self.ipv6_chk = ttk.Checkbutton(opts, text='Include IPv6', variable=self.ipv6_var)
        self.ipv6_chk.pack(side=tk.LEFT, padx=(0,12))
        # Refresh when toggled
        try:
            self.internet_chk.configure(command=self.refresh_analysis)
            self.ipv6_chk.configure(command=self.refresh_analysis)
        except Exception:
            pass
        ttk.Label(opts, text='Ignore IPs (,):').pack(side=tk.LEFT)
        self.ignore_var = tk.StringVar()
        self.ignore_entry = ttk.Entry(opts, textvariable=self.ignore_var, width=40)
        self.ignore_entry.pack(side=tk.LEFT, padx=(4,12))
        # Enter to refresh
        self.router_entry.bind('<Return>', lambda e: self.refresh_analysis())
        self.ignore_entry.bind('<Return>', lambda e: self.refresh_analysis())
        
        sec = ttk.Frame(self)
        sec.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,8))
        ttk.Label(sec, text='Watch countries:').pack(side=tk.LEFT)
        self.watch_vars = {}
        default_watch = {'CN', 'RU', 'KP'}
        for code, label in [('CN','China'), ('RU','Russia'), ('KP','North Korea'), ('IR','Iran'), ('SY','Syria')]:
            var = tk.BooleanVar(value=code in default_watch)
            self.watch_vars[code] = var
            ttk.Checkbutton(sec, text=f'{label} ({code})', variable=var, command=self.refresh_analysis).pack(side=tk.LEFT, padx=(0,4))
        self.flagged_btn = ttk.Button(sec, text='Flagged...', command=self.show_flagged, state=tk.DISABLED)
        self.flagged_btn.pack(side=tk.LEFT, padx=(8,0))

        # Plan / Cap controls
        cap = ttk.Frame(self)
        cap.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,8))
        ttk.Label(cap, text='Monthly Cap (GB):').pack(side=tk.LEFT)
        self.cap_var = tk.StringVar(value='')
        self.cap_entry = ttk.Entry(cap, textvariable=self.cap_var, width=10)
        self.cap_entry.pack(side=tk.LEFT, padx=(4,12))
        ttk.Label(cap, text='Warn %:').pack(side=tk.LEFT)
        self.warn_var = tk.StringVar(value='0.90')
        self.warn_entry = ttk.Entry(cap, textvariable=self.warn_var, width=6)
        self.warn_entry.pack(side=tk.LEFT, padx=(4,12))
        self.cap_status = tk.StringVar(value='')
        ttk.Label(cap, textvariable=self.cap_status).pack(side=tk.LEFT)
        # Enter bindings
        self.cap_entry.bind('<Return>', lambda e: self.refresh_analysis())
        self.warn_entry.bind('<Return>', lambda e: self.refresh_analysis())

        # Naming controls
        namebar = ttk.Frame(self)
        namebar.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,8))
        ttk.Label(namebar, text='Device name for selection:').pack(side=tk.LEFT)
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(namebar, textvariable=self.name_var, width=32)
        self.name_entry.pack(side=tk.LEFT, padx=(4,4))
        ttk.Button(namebar, text='Assign', command=self.assign_name).pack(side=tk.LEFT)
        # Press Enter in name field to assign
        self.name_entry.bind('<Return>', lambda e: self.assign_name())
        ttk.Button(namebar, text='Save Names', command=self.save_names).pack(side=tk.LEFT, padx=(8,0))
        ttk.Button(namebar, text='Load Names', command=self.load_names).pack(side=tk.LEFT, padx=(4,0))

        # Treeview for results
        cols = ('rank','name','provider','ip','top_out_peer','top_in_peer','avg_mb_s','mb_hour','mb_month','flag')
        self.column_labels = {
            'rank':'Rank', 'name':'Name', 'provider':'Provider', 'ip':'IP',
            'top_out_peer':'Top Out Dest', 'top_in_peer':'Top In Source',
            'avg_mb_s':'Avg MB/s', 'mb_hour':'MB/hour', 'mb_month':'MB/month', 'flag':'Flag'
        }
        self.all_columns = cols
        self.visible_columns = list(cols)
        self.hidden_columns: Set[str] = set()
        self.tree = ttk.Treeview(self, columns=cols, show='headings', displaycolumns=self.visible_columns)
        headings = [
            ('rank','Rank'), ('name','Name'), ('provider','Provider'), ('ip','IP'),
            ('top_out_peer','Top Out Dest'), ('top_in_peer','Top In Source'),
            ('avg_mb_s','Avg MB/s'), ('mb_hour','MB/hour'), ('mb_month','MB/month'), ('flag','Flag')
        ]
        for key, text in headings:
            self.tree.heading(key, text=text)
        self.tree.column('rank', width=60, anchor='e')
        self.tree.column('name', width=160, anchor='w')
        self.tree.column('provider', width=140, anchor='w')
        self.tree.column('ip', width=160, anchor='w')
        self.tree.column('top_out_peer', width=160, anchor='w')
        self.tree.column('top_in_peer', width=160, anchor='w')
        for key in ('avg_mb_s','mb_hour','mb_month','flag'):
            self.tree.column(key, width=100, anchor='e')
        for key in cols:
            self.tree.column(key, stretch=True)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0,8))

        # Scrollbars
        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.bind('<Button-3>', self.show_col_menu)
        self.tree.bind('<ButtonPress-1>', self.on_tree_press)
        self.tree.bind('<ButtonRelease-1>', self.on_tree_release)
        self.tree.bind('<Configure>', self.on_tree_configure)

        # Data holders
        self._names: Dict[str, str] = {}
        self._duration_sec: float = 0.0
        self._peer_out: Dict[str, Dict[str, int]] = {}
        self._peer_in: Dict[str, Dict[str, int]] = {}
        self._flagged_details: List[Tuple[str, str, str, float]] = []  # (device, ext_ip, country, MB)
        self._dns_cache: Dict[str, str] = {}
        self._dns_pending: Set[str] = set()
        self._country_cache: Dict[str, Optional[str]] = {}
        self._country_pending: Set[str] = set()
        self._last_column_widths: Dict[str, int] = {}
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Row styling tags
        try:
            self.tree.tag_configure('flag', background='#FFF59D')   # yellow
            self.tree.tag_configure('over', background='#FFCDD2')   # light red
            self.tree.tag_configure('near', background='#FFE0B2')   # light orange
        except Exception:
            pass

    def show_about(self) -> None:
        msg = (
            'GME TrafficGuard (PCAP Usage)\n\n'
            '- Opens PCAP files (classic .pcap) with Ethernet and LINKTYPE_NG40 support.\n'
            '- Lists devices (IP) by bandwidth usage in MB (out/in/total).\n'
            '- Filter to only device↔router traffic by specifying the Router IP.\n'
            '- Ignore selected IPs; assign and save device names.\n'
            '- Optional hostname lookup via 8.8.8.8, country watchlist and XLSX export.\n\n'
            'Designed and built by Dan Gibson & Codex 2025 (Gibson Marine Electrical LTD).'
        )
        messagebox.showinfo('About', msg)

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def decorate_ip(self, ip: str) -> str:
        if not ip:
            return ''
        nm = self._names.get(ip)
        host = self._dns_cache.get(ip) if self.resolve_dns_var.get() else None
        provider = guess_provider(host or ip) if (host or ip) else None
        parts = [p for p in (nm, host) if p]
        if provider:
            parts.append(f"[{provider}]")
        if parts:
            return f"{' | '.join(parts)} ({ip})"
        return ip

    def describe_peer(self, ip: str) -> str:
        if not ip:
            return ''
        host = self._dns_cache.get(ip) if self.resolve_dns_var.get() else None
        provider = guess_provider(host or ip) if (host or ip) else None
        name = self._names.get(ip)
        pieces = [p for p in (name, host) if p]
        if provider:
            pieces.append(f"[{provider}]")
        base = ' | '.join(pieces) if pieces else ''
        return f"{base} ({ip})" if base else ip

    def open_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title='Select PCAP file',
            filetypes=[('PCAP files','*.pcap'), ('All files','*.*')],
            initialdir=os.getcwd(),
        )
        if not path:
            return
        self._pcap_path = path
        self.set_status('Parsing...')
        self.open_btn.config(state=tk.DISABLED)
        self.refresh_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)

        def worker():
            try:
                router = self.router_var.get().strip() or None
                stats, duration, peer_out, peer_in = analyze_pcap(path, router, self.internet_var.get(), self.ipv6_var.get())
            except Exception as e:
                self.after(0, lambda: self.on_parse_error(str(e)))
                return
            self.after(0, lambda: self.on_parse_done(stats, duration, peer_out, peer_in))

        threading.Thread(target=worker, daemon=True).start()

    def on_parse_error(self, msg: str) -> None:
        self.set_status('Error')
        self.open_btn.config(state=tk.NORMAL)
        messagebox.showerror('Parse Error', f'Failed to parse PCAP:\n\n{msg}')

    def on_parse_done(self, stats: Dict[str, IpStats], duration: float, peer_out: Dict[str, Dict[str, int]], peer_in: Dict[str, Dict[str, int]]) -> None:
        self._stats = stats
        self._duration_sec = max(0.0, duration)
        self._peer_out = peer_out
        self._peer_in = peer_in
        all_ips: Set[str] = set(stats.keys())
        for mp in (peer_out, peer_in):
            for _k, d in mp.items():
                all_ips.update(d.keys())
        self.schedule_dns_resolution(all_ips)
        if any(var.get() for var in self.watch_vars.values()):
            self.schedule_country_resolution(all_ips)
        self.rebuild_view()
        self.open_btn.config(state=tk.NORMAL)
        self.refresh_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)

    def export_xlsx_action(self) -> None:
        if not self._stats:
            return
        save_path = filedialog.asksaveasfilename(
            title='Export to Excel',
            defaultextension='.xlsx',
            filetypes=[('Excel Workbook','*.xlsx')],
            initialfile='traffic_usage.xlsx'
        )
        if not save_path:
            return
        # Build rows ordered by current view with current columns
        rows = []
        for item_id in self.tree.get_children():
            vals = self.tree.item(item_id, 'values')
            # Values align to: rank,name,provider,ip,top_out_peer,top_in_peer,avg_mb_s,mb_hour,mb_month,flag
            rank = int(vals[0])
            name = str(vals[1])
            provider = str(vals[2])
            ip = str(vals[3])
            top_out_peer = str(vals[4])
            top_in_peer = str(vals[5])
            avg_mb_s = float(vals[6])
            mb_hour = float(vals[7])
            mb_month = float(vals[8])
            flag = str(vals[9])
            rows.append((rank, name, provider, ip, top_out_peer, top_in_peer, avg_mb_s, mb_hour, mb_month, flag))
        try:
            export_xlsx(rows, save_path)
        except Exception as e:
            messagebox.showerror('Export Failed', f'Could not write XLSX file:\n\n{e}')
            return
        messagebox.showinfo('Export Complete', f'Exported to:\n{save_path}')

    # Helpers
    def parse_ignored(self) -> set:
        txt = (self.ignore_var.get() or '').strip()
        if not txt:
            return set()
        return {p.strip() for p in txt.split(',') if p.strip()}

    def schedule_dns_resolution(self, ips: Set[str]) -> None:
        if not self.resolve_dns_var.get():
            return
        todo = [ip for ip in ips if ip not in self._dns_cache and ip not in self._dns_pending and not is_private_ip(ip)]
        if not todo:
            return
        self._dns_pending.update(todo)

        def worker():
            changed = False
            for ip in todo:
                host = nslookup_host(ip)
                if host is not None:
                    self._dns_cache[ip] = host
                    if ip not in self._names:
                        self._names[ip] = host
                    changed = True
                self._dns_pending.discard(ip)
            if changed:
                self.after(0, self.rebuild_view)
        threading.Thread(target=worker, daemon=True).start()

    def schedule_country_resolution(self, ips: Set[str]) -> None:
        todo = [ip for ip in ips if ip not in self._country_cache and ip not in self._country_pending and not is_private_ip(ip)]
        if not todo:
            return
        self._country_pending.update(todo)

        def worker():
            changed = False
            for ip in todo:
                cc = lookup_country_http(ip)
                self._country_cache[ip] = cc
                self._country_pending.discard(ip)
                if cc:
                    changed = True
            if changed:
                self.after(0, self.rebuild_view)
        threading.Thread(target=worker, daemon=True).start()

    def lookup_country_async(self, ip: str) -> Optional[str]:
        if not ip:
            return None
        if ip in self._country_cache:
            return self._country_cache[ip]
        if ip in self._country_pending:
            return None
        self.schedule_country_resolution({ip})
        return None

    # Column helpers
    def autosize_columns(self) -> None:
        fnt = tkfont.nametofont('TkDefaultFont')
        pad = 22
        for col in self.visible_columns:
            header = self.column_labels.get(col, col)
            texts = [header]
            for item in self.tree.get_children():
                texts.append(self.tree.set(item, col))
            max_px = max((fnt.measure(t) for t in texts), default=60)
            width = min(max(max_px + pad, 80), 360)
            self.tree.column(col, width=width)

    def hide_column(self, col: str) -> None:
        if col not in self.visible_columns or len(self.visible_columns) <= 1:
            return
        self.visible_columns = [c for c in self.visible_columns if c != col]
        self.hidden_columns.add(col)
        self.tree['displaycolumns'] = self.visible_columns
        self.autosize_columns()

    def unhide_column(self, col: str) -> None:
        if col not in self.hidden_columns:
            return
        self.hidden_columns.discard(col)
        # Restore order according to all_columns
        self.visible_columns = [c for c in self.all_columns if c not in self.hidden_columns]
        self.tree['displaycolumns'] = self.visible_columns
        self.autosize_columns()

    def unhide_all(self) -> None:
        self.hidden_columns.clear()
        self.visible_columns = list(self.all_columns)
        self.tree['displaycolumns'] = self.visible_columns
        self.autosize_columns()

    def show_col_menu(self, event) -> None:
        menu = tk.Menu(self, tearoff=0)
        hide_menu = tk.Menu(menu, tearoff=0)
        for col in self.visible_columns:
            if len(self.visible_columns) <= 1:
                state = tk.DISABLED
            else:
                state = tk.NORMAL
            hide_menu.add_command(label=self.column_labels.get(col, col), state=state, command=lambda c=col: self.hide_column(c))
        menu.add_cascade(label='Hide column', menu=hide_menu)

        unhide_menu = tk.Menu(menu, tearoff=0)
        if self.hidden_columns:
            for col in sorted(self.hidden_columns, key=lambda c: self.all_columns.index(c)):
                unhide_menu.add_command(label=self.column_labels.get(col, col), command=lambda c=col: self.unhide_column(c))
        else:
            unhide_menu.add_command(label='(none)', state=tk.DISABLED)
        menu.add_cascade(label='Unhide column', menu=unhide_menu)
        menu.add_command(label='Unhide all', command=self.unhide_all)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def on_tree_press(self, _event=None) -> None:
        self._last_column_widths = {c: int(self.tree.column(c, 'width')) for c in self.visible_columns}

    def on_tree_release(self, _event=None) -> None:
        self.balance_columns()

    def on_tree_configure(self, _event=None) -> None:
        # Keep columns filling available space on resize
        self.balance_columns(fill_only=True)

    def balance_columns(self, fill_only: bool = False) -> None:
        if not self.visible_columns:
            return
        tree_width = max(1, int(self.tree.winfo_width()))
        current = {c: int(self.tree.column(c, 'width')) for c in self.visible_columns}
        prev = self._last_column_widths or current
        total = sum(current.values())
        if tree_width <= 1:
            return

        # Identify most-changed column to preserve user intent
        changed_col = self.visible_columns[-1]
        max_delta = -1
        for c in self.visible_columns:
            delta = abs(current[c] - prev.get(c, current[c]))
            if delta > max_delta:
                max_delta = delta
                changed_col = c

        diff = total - tree_width
        if abs(diff) < 2 and fill_only:
            return
        others = [c for c in self.visible_columns if c != changed_col]
        if not others:
            return

        total_others = sum(current[c] for c in others)
        if total_others <= 0:
            return
        for c in others:
            weight = current[c] / total_others if total_others else 1 / len(others)
            adj = diff * weight
            new_w = max(60, int(round(current[c] - adj)))
            current[c] = new_w

        # Fix rounding drift
        total_after = sum(current.values())
        drift = tree_width - total_after
        tail = others[-1]
        current[tail] = max(60, current[tail] + drift)

        for c, w in current.items():
            self.tree.column(c, width=w)
        self._last_column_widths = current

    def rebuild_view(self) -> None:
        # Build item tuples with filtering and computed metrics
        MB = 1_000_000.0
        duration = self._duration_sec if self._duration_sec > 0 else 0.0
        ignored = self.parse_ignored()
        router = self.router_var.get().strip()
        watch = {code for code, var in self.watch_vars.items() if var.get()}
        items = []
        flagged_details: List[Tuple[str, str, str, float]] = []
        for ip, s in self._stats.items():
            if ip in ignored:
                continue
            name = self._names.get(ip, '')
            dns_host = self._dns_cache.get(ip) if self.resolve_dns_var.get() else ''
            display_name = name
            if dns_host:
                display_name = f"{name} | {dns_host}" if name else dns_host
            provider = guess_provider(dns_host or ip) or ''
            out_b = s.bytes_src
            in_b = s.bytes_dst
            total_b = s.bytes_total
            total_mb = total_b / MB
            avg_mb_s = (total_b / MB / duration) if duration > 0 else 0.0
            mb_hour = avg_mb_s * 3600.0
            mb_month = avg_mb_s * (30.0 * 86400.0)
            # Determine top peers
            top_out_peer = ''
            top_in_peer = ''
            if ip in self._peer_out and self._peer_out[ip]:
                top_out_peer = max(self._peer_out[ip].items(), key=lambda kv: kv[1])[0]
            if ip in self._peer_in and self._peer_in[ip]:
                top_in_peer = max(self._peer_in[ip].items(), key=lambda kv: kv[1])[0]
            # Decorate peers with names if available
            top_out_disp = self.describe_peer(top_out_peer) if top_out_peer else ''
            top_in_disp = self.describe_peer(top_in_peer) if top_in_peer else ''
            # Flag if any watched country among any peers (union of in/out)
            flag = ''
            if watch:
                merged = {}
                for m in (self._peer_out.get(ip, {}), self._peer_in.get(ip, {})):
                    for k,v in m.items():
                        merged[k] = merged.get(k, 0) + v
                for ext_ip, bytes_ in merged.items():
                    cc = self.lookup_country_async(ext_ip)
                    if cc and cc.upper() in watch:
                        flag = f'WATCH:{cc.upper()}'
                        flagged_details.append((display_name or ip, ext_ip, cc.upper(), bytes_ / MB))
            items.append((ip, display_name, provider, top_out_disp, top_in_disp, total_mb, avg_mb_s, mb_hour, mb_month, flag))
        items.sort(key=lambda x: x[5], reverse=True)  # by total_mb

        # Populate tree
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Determine cap thresholds
        cap_mb = 0.0
        warn_ratio = 0.9
        try:
            if self.cap_var.get().strip():
                cap_gb = float(self.cap_var.get().strip())
                if cap_gb > 0:
                    cap_mb = cap_gb * 1000.0
        except Exception:
            cap_mb = 0.0
        try:
            wr = float(self.warn_var.get().strip())
            if wr > 1.0:
                warn_ratio = wr / 100.0
            elif 0 < wr < 1.0:
                warn_ratio = wr
        except Exception:
            warn_ratio = 0.9

        cap_summary_txt = ''
        for idx, (ip, name, provider, top_out_disp, top_in_disp, total_mb, avg_mb_s, mb_hour, mb_month, flag) in enumerate(items, start=1):
            tags = ()
            # Country flag takes precedence
            if flag:
                tags = ('flag',)
            elif cap_mb > 0:
                if mb_month >= cap_mb:
                    tags = ('over',)
                elif mb_month >= warn_ratio * cap_mb:
                    tags = ('near',)
            self.tree.insert('', 'end', values=(idx, name, provider, ip, top_out_disp, top_in_disp, f"{avg_mb_s:.6f}", f"{mb_hour:.3f}", f"{mb_month:.3f}", flag), tags=tags)
            if idx == 1 and cap_mb > 0:
                cap_summary_txt = f"Projected {mb_month/1000.0:.2f} GB vs cap {cap_mb/1000.0:.2f} GB (warn @ {warn_ratio*100:.0f}%)"

        self.set_status(f'Parsed {len(items)} devices from {os.path.basename(self._pcap_path or "")}')
        self.cap_status.set(cap_summary_txt)
        self._flagged_details = flagged_details
        self.flagged_btn.config(state=(tk.NORMAL if flagged_details else tk.DISABLED))
        self.autosize_columns()

    def refresh_analysis(self) -> None:
        if not self._pcap_path:
            return
        self.set_status('Parsing...')
        self.open_btn.config(state=tk.DISABLED)
        self.refresh_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)

        def worker():
            try:
                router = self.router_var.get().strip() or None
                stats, duration, peer_out, peer_in = analyze_pcap(self._pcap_path, router, self.internet_var.get(), self.ipv6_var.get())
            except Exception as e:
                self.after(0, lambda: self.on_parse_error(str(e)))
                return
            self.after(0, lambda: self.on_parse_done(stats, duration, peer_out, peer_in))

        threading.Thread(target=worker, daemon=True).start()

    def on_tree_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], 'values')
        if not vals:
            return
        ip = vals[3]
        self.name_var.set(self._names.get(ip, ''))

    def assign_name(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], 'values')
        if not vals:
            return
        ip = vals[3]
        name = self.name_var.get().strip()
        if name:
            self._names[ip] = name
        else:
            self._names.pop(ip, None)
        self.rebuild_view()

    def save_names(self) -> None:
        import json
        path = filedialog.asksaveasfilename(title='Save device names', defaultextension='.json', filetypes=[('JSON','*.json')], initialfile='device_names.json')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self._names, f, indent=2, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror('Save Failed', str(e))

    def load_names(self) -> None:
        import json
        path = filedialog.askopenfilename(title='Load device names', filetypes=[('JSON','*.json'), ('All files','*.*')], initialdir=os.getcwd())
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self._names = json.load(f)
            self.rebuild_view()
        except Exception as e:
            messagebox.showerror('Load Failed', str(e))

    def show_flagged(self) -> None:
        if not self._flagged_details:
            return
        win = tk.Toplevel(self)
        win.title('Flagged Destinations')
        win.geometry('700x400')
        cols = ('device','ext_ip','country','mb')
        tv = ttk.Treeview(win, columns=cols, show='headings')
        tv.heading('device', text='Device')
        tv.heading('ext_ip', text='External IP')
        tv.heading('country', text='Country')
        tv.heading('mb', text='MB')
        tv.column('device', width=200, anchor='w')
        tv.column('ext_ip', width=160, anchor='w')
        tv.column('country', width=80, anchor='w')
        tv.column('mb', width=80, anchor='e')
        for dev, ext, cc, mb in self._flagged_details:
            tv.insert('', 'end', values=(dev, ext, cc, f"{mb:.3f}"))
        tv.pack(fill=tk.BOTH, expand=True)


def main():
    import argparse, json
    parser = argparse.ArgumentParser(description='PCAP Usage Analyzer')
    parser.add_argument('--pcap', help='Path to .pcap to analyze')
    parser.add_argument('--router', help='Router IP to consider edge of LAN (only device<->router traffic included)')
    parser.add_argument('--internet-only', action='store_true', help='Count only device(private) <-> public traffic (exclude LAN-LAN)')
    parser.add_argument('--ignore', help='Comma-separated list of IPs to ignore')
    parser.add_argument('--names', help='JSON file mapping IP -> device name')
    parser.add_argument('--geodb', help='GeoDB CSV (cidr,iso2) for country lookups')
    parser.add_argument('--watch', help='ISO2 watchlist, comma-separated (e.g. CN,RU,KP)')
    parser.add_argument('--export', help='Path to .xlsx export (with --pcap)')
    parser.add_argument('--top', type=int, default=1000, help='Rows to include in CLI export/print')
    args = parser.parse_args()

    if args.pcap:
        stats, duration = None, None
        stats, duration, peer_out, peer_in = analyze_pcap(args.pcap, args.router, args.internet_only)
        names = {}
        if args.names:
            try:
                with open(args.names, 'r', encoding='utf-8') as f:
                    names = json.load(f)
            except Exception:
                names = {}
        ignored = set()
        if args.ignore:
            ignored = {p.strip() for p in args.ignore.split(',') if p.strip()}
        MB = 1_000_000.0
        dur = duration if duration and duration > 0 else 0.0
        geodb = None
        if args.geodb:
            try:
                geodb = GeoDB(); geodb.load_csv_simple(args.geodb)
            except Exception:
                geodb = None
        watch = set()
        if args.watch:
            watch = {c.strip().upper() for c in args.watch.split(',') if c.strip()}
        items = []
        for ip, s in stats.items():
            if ip in ignored:
                continue
            out_b = s.bytes_src
            in_b = s.bytes_dst
            total_b = s.bytes_total
            total_mb = total_b / MB
            avg_mb_s = (total_b / MB / dur) if dur > 0 else 0.0
            mb_hour = avg_mb_s * 3600.0
            mb_month = avg_mb_s * (30.0 * 86400.0)
            # determine top peers
            top_out_peer = max(peer_out.get(ip, {}).items(), key=lambda kv: kv[1])[0] if peer_out.get(ip) else ''
            top_in_peer = max(peer_in.get(ip, {}).items(), key=lambda kv: kv[1])[0] if peer_in.get(ip) else ''
            flag = ''
            if geodb and watch:
                merged = {}
                for m in (peer_out.get(ip, {}), peer_in.get(ip, {})):
                    for k,v in m.items():
                        merged[k] = merged.get(k, 0) + v
                for ext_ip in merged.keys():
                    cc = geodb.lookup(ext_ip)
                    if cc and cc.upper() in watch:
                        flag = 'REVIEW'
                        break
            provider = guess_provider(ip) or ''
            items.append((ip, names.get(ip,''), provider, top_out_peer, top_in_peer, total_mb, avg_mb_s, mb_hour, mb_month, flag))
        items.sort(key=lambda x: x[5], reverse=True)
        rows = [(i+1, name, provider, ip, top_out_peer, top_in_peer, avg_mb_s, mb_hour, mb_month, flag)
                for i, (ip, name, provider, top_out_peer, top_in_peer, total_mb, avg_mb_s, mb_hour, mb_month, flag) in enumerate(items[: args.top ])]
        # Print a simple top list
        for r in rows[: min(20, len(rows)) ]:
            rank, name, provider, ip, top_out_peer, top_in_peer, avg_mb_s, mb_hour, mb_month, flag = r
            disp = f"{rank:4} {ip:>16}"
            if name:
                disp += f" ({name})"
            if provider:
                disp += f" [{provider}]"
            extra = f" [FLAG:{flag}]" if flag else ''
            peers_info = ''
            if top_out_peer or top_in_peer:
                peers_info = f" topOut={top_out_peer} topIn={top_in_peer}"
            print(f"{disp}  avgMB/s={avg_mb_s:.6f} mb_hour={mb_hour:.3f} mb_month={mb_month:.3f}{peers_info}{extra}")
        if args.export:
            export_xlsx(rows, args.export)
            print(f"Exported {len(rows)} rows to {args.export}")
        return

    # No CLI args provided: launch GUI
    app = App()
    app.mainloop()


class GeoDB:
    def __init__(self) -> None:
        self.v4: List[Tuple[ipaddress.IPv4Network, str]] = []
        self.v6: List[Tuple[ipaddress.IPv6Network, str]] = []

    def load_csv_simple(self, path: str) -> None:
        # CSV format: cidr,iso2
        import csv
        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            r = csv.reader(f)
            for row in r:
                if not row or row[0].startswith('#'):
                    continue
                if len(row) < 2:
                    continue
                cidr = row[0].strip()
                iso = row[1].strip().upper()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except Exception:
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    self.v4.append((net, iso))
                else:
                    self.v6.append((net, iso))

    def count_entries(self) -> int:
        return len(self.v4) + len(self.v6)

    def lookup(self, ip_str: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv4Address):
            for net, iso in self.v4:
                if ip in net:
                    return iso
        else:
            for net, iso in self.v6:
                if ip in net:
                    return iso
        return None

if __name__ == '__main__':
    main()
