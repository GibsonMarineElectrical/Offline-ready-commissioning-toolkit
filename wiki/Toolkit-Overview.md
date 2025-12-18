# Toolkit overview

The Offline-ready commissioning toolkit is a working set of docs plus small utilities that run without internet.

## Typical use on site
- Extract the ZIP to a local folder or USB stick
- Launch `GME-Commissioner` as the entry point
- Use the portal to open each tool in its own tab
- Refer to `docs/` for protocol notes and safety references

## Repository layout
| Path | What it contains |
| --- | --- |
| `software/` | Portable Windows tools plus per-tool usage notes |
| `docs/` | Protocol notes, safety cheat sheets, reference docs |
| `commissioning/` | Small site scripts and configuration notes |

## Design goals
- Offline first: no external services required
- Portable: extract, run, remove
- Predictable: fixed default ports per tool
- Low footprint: minimal state stored on disk

