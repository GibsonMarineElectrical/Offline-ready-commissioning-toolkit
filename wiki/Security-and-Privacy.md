# Security and privacy

This toolkit is designed for offline use. Keep it clean on site media.

## Good practice
- Do not store credentials in the toolkit folder.
- Do not store client configuration or vessel data.
- Keep packet captures and logs in a separate, controlled location.
- Treat the laptop as a controlled asset. Lock it down per project rules.

## Repository checks
- GitHub secret scanning is enabled.
- A Gitleaks workflow runs on pushes and pull requests.
- Executables are distributed via Releases. The repository rejects committed `.exe` files.

