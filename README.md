# Offline-ready commissioning toolkit

Offline pack for marine and offshore FAT/SAT work where connectivity is limited. Includes electrical and networking references, safety notes, commissioning aids, and a small set of offline utilities.

## Purpose
- Keep essential references on removable media for ships, yards, and offshore sites.
- Support troubleshooting and temporary local hosting without internet reliance.
- Stay lean by carrying only hard-to-source tools.

## Contents
- docs/ – structured references
  - electrical/pinouts/ – CAN bus, NMEA0183, RS-232/422/485 placeholders
  - networking/protocols/ – Modbus TCP/RTU, serial links, NMEA0183, IP basics
  - commissioning/ – checklist and signal example placeholders
  - system/flowcharts/ – flowchart placeholders
  - safety/ – fire extinguisher classes and ISO safety cheat sheet
- commissioning/ntp-time-update-windows/ – notes and batch for updating Windows time sources on site
- software/http-webserver-host/ – Windows/.NET local file browser for offline hosting
- software/offline-installers/ – hard-to-find installers (converter, ECDIS simulator, terminal)
- software/legacy-browser/ – VBScript helper for legacy IE use

## Field notes
- Keep binaries read-only and scan with current AV before deployment.
- Avoid adding common installers or any credentials/customer data.
- Share only the docs and tools needed for the specific vessel or site.

## Integrity and release
- Binaries are tracked for auditability; note source, version, and hash when they change.
- Large build outputs under software/http-webserver-host can be rebuilt or pruned before packaging.
- Licensing and contribution details sit in the root placeholders; complete them before formal release.
