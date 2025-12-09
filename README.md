# Offline-ready-commissioning-toolkit
<<<<<<< Updated upstream
Offline-ready commissioning toolkit

To be populated as and when time allows. This is a low priority currently. 
=======

Offline toolkit for commissioning work when network access is limited: documents, maintenance cards, pinouts, reference material, and a curated set of hard-to-find installers.

## Repo layout
- docs/ - commissioning documents and maintenance cards
- software/ - only hard-to-find installers kept offline
- software/portable-apps/ - portable builds kept for quick drop-in use
- pinouts/ - RS-232/422/485, NMEA0183, and CAN bus pinouts
- reference/ - protocols, commissioning checks, signal examples, and flowcharts

## Software policy
This repository only stores hard-to-find installers. Common tools are listed below for download elsewhere.

## Portable apps
Drop your portable app layout into `software/portable-apps/` to keep ready-to-run builds handy.

## Common tools (not mirrored here)
- PuTTY
- Cyberduck
- FileZilla
- WinSCP
- Resilio Sync
- Arduino CLI
- VirtualBox

## Recommended for offline commissioning on Windows (not mirrored here)
- Wireshark + Npcap for packet capture/analysis
- nmap for discovery and port scanning
- RealTerm or Tera Term for serial console work
- 7-Zip for handling archives
- Notepad++ for quick config edits
- Rufus for creating bootable media
- Git for Windows with bundled OpenSSH for offline versioning
>>>>>>> Stashed changes
