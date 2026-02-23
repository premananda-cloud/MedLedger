@echo off
echo ============================================
echo  MedLedger Desktop Client - Windows Build
echo ============================================

echo.
echo [1/3] Installing dependencies...
pip install -r requirements.txt

echo.
echo [2/3] Building executable...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name MedLedger ^
  --hidden-import cryptography ^
  --hidden-import cryptography.hazmat.primitives ^
  --hidden-import cryptography.hazmat.backends ^
  --hidden-import requests ^
  --add-data "config.py;." ^
  --add-data "core;core" ^
  --add-data "client;client" ^
  --add-data "ui;ui" ^
  main.py

echo.
echo [3/3] Done!
echo Output: dist\MedLedger.exe
echo.
echo Share dist\MedLedger.exe with judges.
echo Users just double-click — no Python install needed.
pause
