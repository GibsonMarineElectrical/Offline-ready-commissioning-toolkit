# Offline-ready commissioning toolkit

Field-ready pack for marine and offshore electrical commissioning when network access is limited. Provides pinouts, protocol references, safety notes, commissioning aids, and a small set of offline installers and utilities.

## Scope and use cases
- Support FAT/SAT and ad-hoc troubleshooting without relying on the internet.
- Keep electrical, networking, and safety references available on removable media.
- Host files locally when required via the bundled Windows/.NET file browser.

## Repository layout
- docs/ – structured references.
  - electrical/pinouts/ – CAN bus, NMEA0183, and RS-232/422/485 placeholders.
  - 
etworking/protocols/ – Modbus TCP/RTU, serial links, NMEA0183, IP basics.
  - commissioning/ – checks and signal examples (placeholders ready to populate).
  - system/flowcharts/ – flowchart placeholders.
  - safety/ – fire extinguisher classes and ISO safety cheatsheet.
- commissioning/ntp-time-update-windows/ – scripts/notes for updating Windows time sources during site work.
- software/http-webserver-host/ – Windows/.NET local file browser for offline hosting.
- software/offline-installers/ – hard-to-find installers (converter, ECDIS simulator, terminal).
- software/legacy-browser/ – VBScript helper for legacy IE usage.

## Operating guidance
- Treat binaries as read-only and scan with current AV before field use.
- Do not add common installers; keep only items that are difficult to source offline.
- Do not store credentials, customer data, or sensitive configs.
- When preparing media for site use, copy only the required tools plus relevant docs/checks.

## Contribution and maintenance
- Complete the placeholders in LICENSE, CHANGELOG.md, CONTRIBUTING.md, and SECURITY.md before distribution.
- When adding binaries, record source, version, and hash in commit messages for audit trails.
- Consider pruning/rebuilding large outputs in software/http-webserver-host if repository size becomes an issue.
