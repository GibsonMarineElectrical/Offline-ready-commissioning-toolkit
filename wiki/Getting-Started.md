# Getting started (Windows)

## Download
1. Open the repository `Releases` page on GitHub.
2. Download the latest `Offline-ready-commissioning-toolkit` ZIP.
3. Extract it to a writable folder, for example `C:\Toolkit\` or a project folder.

Executables are distributed via GitHub Releases. They are not committed to this repository.

## Run the portal
1. Start `software/GME-Commissioner/GME-Commissioner.exe`.
2. Open `http://127.0.0.1:8080` in a browser.

If Windows Firewall prompts, allow only what the job needs. Prefer Private networks. Avoid Public networks.

## Update
- Keep each release in its own folder.
- Copy only what you need to site media.
- Delete older folders when the job is finished.

## Where files get written
Most tools create small state files next to the EXE. Avoid `C:\Program Files\...` since it is not writable without elevation.

