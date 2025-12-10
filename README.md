# Offline-ready commissioning toolkit

Marine-focused offline pack for FAT/SAT and yard/offshore electrical commissioning when connectivity is unreliable. Provides electrical and networking references, safety notes, commissioning aids, and a curated set of offline utilities.

## Purpose
- Keep critical references on removable media for ship, yard, and offshore sites.
- Support FAT/SAT, troubleshooting, and temporary local hosting without internet.
- Minimise footprint and avoid common installers; only retain hard-to-source tools.

## Repository layout
- docs/ – structured references.
  - electrical/pinouts/ – CAN bus, NMEA0183, and RS-232/422/485 placeholders.
  - 
etworking/protocols/ – Modbus TCP/RTU, serial links, NMEA0183, IP basics.
  - commissioning/ – checks and signal example placeholders.
  - system/flowcharts/ – flowchart placeholders.
  - safety/ – fire extinguisher classes and ISO safety cheat sheet.
- commissioning/ntp-time-update-windows/ – scripts and notes for refreshing Windows time sources on site.
- software/http-webserver-host/ – Windows/.NET local file browser for offline hosting.
- software/offline-installers/ – hard-to-find installers (converter, ECDIS simulator, terminal).
- software/legacy-browser/ – VBScript helper for legacy IE usage.

## Using this toolkit
- Copy required docs and tools to removable media before travel.
- Run software/http-webserver-host/file-web-browser.exe to serve files locally when needed.
- Use commissioning/ntp-time-update-windows/ntp-update.bat only with admin approval and the accompanying notes.
- Scan all binaries with current AV before use; keep executables read-only.
- Do not add credentials, customer data, or sensitive configs.

## Safety, integrity, and audit
- Record source, version, and hash in commit messages when adding binaries.
- Large build outputs exist in software/http-webserver-host; prune or rebuild for distributions as required.
- Confirm licensing in LICENSE and complete CHANGELOG.md, CONTRIBUTING.md, and SECURITY.md before client release.
