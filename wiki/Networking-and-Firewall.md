# Networking and firewall

Several tools expose a local web UI. Default bind addresses vary by tool.

## Bind addresses
- `127.0.0.1` means local-only. Other devices cannot connect.
- `0.0.0.0` means LAN-accessible. Any host that can reach the PC can connect.

Check the per-tool `README.md` before using a tool on a shared network.

## Firewall guidance (Windows)
- Prefer Private networks.
- Avoid Public networks.
- Keep inbound rules scoped to the ports you need.
- Limit remote IP ranges when the job allows it.

## Port list
See [Software](Software) for default ports.

