@echo off
REM Build portable onefile EXE (with console) for GME CalcServer
python -m PyInstaller --onefile --console --name GME-CalcServer calc_server.py
