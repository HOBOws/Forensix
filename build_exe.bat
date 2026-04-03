@echo off
cd /d "%~dp0"
title FORENSIX - EXE Builder
echo.
echo ============================================
echo   FORENSIX - Build Standalone EXE
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

:: Check forensix.py exists
if not exist forensix.py (
    echo [ERROR] forensix.py not found in %CD%
    echo Place forensix.py and build_exe.bat in the same folder.
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install PyQt6 matplotlib Pillow pyinstaller --quiet

echo.
echo [2/3] Cleaning old build...
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist
if exist Forensix.spec del Forensix.spec

echo.
echo [3/3] Building Forensix.exe ...
python -m PyInstaller --onefile --windowed --name Forensix ^
    --hidden-import PyQt6.QtCore ^
    --hidden-import PyQt6.QtGui ^
    --hidden-import PyQt6.QtWidgets ^
    --hidden-import PyQt6.sip ^
    --hidden-import matplotlib.backends.backend_qtagg ^
    --hidden-import matplotlib.backends.backend_qt ^
    --hidden-import PIL.Image ^
    --hidden-import numpy ^
    --exclude-module tkinter ^
    --exclude-module PySide2 ^
    --exclude-module PySide6 ^
    forensix.py

echo.
if exist dist\Forensix.exe (
    echo ============================================
    echo   SUCCESS
    echo   dist\Forensix.exe is ready.
    echo   Copy it anywhere - no install needed.
    echo ============================================
) else (
    echo [ERROR] Build failed. Check output above.
    echo You can still run the app with:
    echo   python forensix.py
)
echo.
pause
