# IP (IPv4) basics quick reference

## Addressing
- Use static addressing for field devices when offline; document IP, subnet mask, gateway, VLAN if used.
- Common private ranges: 192.168.x.x/24, 10.x.x.x/24. Avoid conflicts with vessel/yard ranges.
- Example static: IP 192.168.10.20, mask 255.255.255.0, gateway 192.168.10.1 (if routed).

## Testing
- `ping 192.168.10.20` to verify reachability (if ICMP allowed).
- `arp -a` to confirm MAC learned; clear with `arp -d *` if stale.
- `telnet 192.168.10.20 502` (or `Test-NetConnection -ComputerName 192.168.10.20 -Port 502` in PowerShell) to check TCP ports like Modbus TCP.

## Cabling and speed/duplex
- Auto-negotiation usually fine; hard-set only if required. Mismatched duplex causes drops.
- Use proper patch vs crossover if devices lack auto-MDI/MDIX (rare on modern gear).

## VLANs
- Note access vs trunk; tag configuration on switches. Field devices typically untagged on an access port.

## Logging
- Capture with Wireshark/Npcap for packet inspection; filter by IP or TCP port (e.g., `tcp.port==502`).
