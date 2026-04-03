@echo off
cd /d "%~dp0"
title FORENSIX - Installer
echo.
echo ============================================
echo   FORENSIX - Install and Launch
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo.
    echo Please install Python 3.10 or newer from:
    echo   https://python.org/downloads
    echo.
    echo IMPORTANT: During install, check the box that says
    echo   "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.

echo [1/2] Installing required packages...
python -m pip install --upgrade pip --quiet
python -m pip install PyQt6 matplotlib Pillow --quiet

if errorlevel 1 (
    echo.
    echo [ERROR] Package installation failed.
    echo Try running this file as Administrator.
    pause
    exit /b 1
)

echo [OK] All packages installed.
echo.
echo [2/2] Launching Forensix...
echo.
python forensix.py

if errorlevel 1 (
    echo.
    echo [ERROR] Forensix crashed on launch.
    echo Check forensix_crash.log in this folder for details.
    pause
)
