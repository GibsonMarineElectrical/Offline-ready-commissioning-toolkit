@echo off
REM Build portable onefile EXE (console) for GME Commissioner portal
python -m PyInstaller --onefile --console --name GME-Commissioner commissioner_server.py
