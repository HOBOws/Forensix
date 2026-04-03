# Forensix
steganography and extraction detection suite 

============================================================
  FORENSIX — Digital Forensics Analysis Suite
  Version 2.0
============================================================

FORENSIX is a standalone digital forensics tool for
analyzing files for hidden content, embedded payloads,
steganography, and anomalous data. It requires no internet
connection after installation and runs entirely locally.

------------------------------------------------------------
  QUICK START
------------------------------------------------------------

Option A — Run directly (recommended for first use):
  1. Place forensix.py and install_and_run.bat in the
     same folder.
  2. Double-click install_and_run.bat
  3. The installer will handle everything and launch
     the app automatically.

Option B — Build a standalone EXE (no Python needed later):
  1. Place forensix.py and build_exe.bat in the same folder.
  2. Double-click build_exe.bat
  3. When complete, your EXE will be at:
       dist\Forensix.exe
  4. Copy Forensix.exe anywhere — it runs with no
     dependencies on any other machine.

------------------------------------------------------------
  SYSTEM REQUIREMENTS
------------------------------------------------------------

  Operating System : Windows 10 or Windows 11 (64-bit)
  Python           : 3.10 or newer
  RAM              : 512 MB minimum, 2 GB recommended
                     (large files use more memory)
  Disk space       : ~500 MB (Python + packages + EXE)
  Display          : Any resolution (runs fullscreen)

  Python download  : https://python.org/downloads
  IMPORTANT: During Python install, check the box that
  reads "Add Python to PATH" — without this the
  installer scripts will not find Python.

------------------------------------------------------------
  DEPENDENCIES
------------------------------------------------------------

All dependencies are installed automatically by the
install_and_run.bat or build_exe.bat scripts.
You do not need to install anything manually.

  Package       Version    Purpose
  ------------- ---------- ---------------------------------
  PyQt6         6.x        GUI framework (windows, widgets,
                           painting, animation)
  matplotlib    3.x        Entropy graph rendering
  Pillow        10.x+      Image reading for LSB analysis
                           and noise map generation
  numpy         1.23+      Numerical arrays (matplotlib dep)
  pyinstaller   6.x        EXE builder (build_exe.bat only)

  Optional (not installed automatically):
  exiftool      any        Enhanced metadata extraction.
                           If installed and on PATH, Forensix
                           will use it automatically.
                           Download: https://exiftool.org

------------------------------------------------------------
  WHAT FORENSIX DOES
------------------------------------------------------------

FORENSIX analyzes any file and presents findings across
8 dedicated tabs:

  Overview       File hashes (MD5, SHA1, SHA256, SHA512,
                 CRC32), risk summary, anomaly count.

  Metadata       File timestamps, permissions, MIME type
                 detection via system "file" command,
                 full EXIF data if exiftool is installed.

  Strings        All printable ASCII and UTF-16 strings
                 extracted from the file. Filterable by
                 keyword and minimum length in real time.

  Anomalies      Automatic checks for:
                 - LSB steganography (images)
                 - Data appended after JPEG/PNG EOF
                 - Null byte padding
                 - Entropy spikes (encrypted regions)
                 - Appended ZIP archives

  Scanner        Magic byte signature scan across 90+
                 file format signatures including images,
                 video, audio, documents, email, archives,
                 executables, databases, crypto, firmware.
                 Includes confidence scoring (HIGH/MEDIUM/
                 LOW), size plausibility filtering, hex
                 preview, and duplicate collapsing.
                 Supports custom signatures.

  Entropy        Shannon entropy graph across the full
                 file, with:
                 - Colored bands per detected file region
                 - Spike/dip annotations naming the
                   responsible file type
                 - Side legend listing all correlated files
                 - Edge table with nearest file correlation

  Steganography  Full LSB steganography analysis:
                 - LSB ratio per channel (R/G/B)
                 - Chi-square statistical test
                 - Chi-square variance (key detection signal)
                 - Auto-extraction of hidden text or files
                 - Visual LSB noise map image
                 - DETECTED / SUSPECTED / CLEAN verdict
                 Supports PNG, BMP, TIFF, JPEG.

  Extractor      Extract embedded files to disk from any
                 detected magic hit. Supports custom magic
                 signatures for rescan. HIGH confidence
                 bulk extraction in one click.

Additional features:
  - Breaking machine animation overlay during analysis
  - HTML report export
  - Analysis runs in a background thread (UI never freezes)
  - Crash log written to forensix_crash.log on error

------------------------------------------------------------
  SUPPORTED FILE FORMATS (Scanner)
------------------------------------------------------------

  Images    : JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, PSD
  Video     : MP4, AVI, MKV, MOV, WMV, FLV, MPEG, WebM,
              3GP
  Audio     : MP3, WAV, FLAC, OGG, AAC, M4A, AIFF, WMA,
              Opus, Speex, AMR, MIDI
  Documents : PDF, RTF, DOCX, DOC, XLSX, XLS, PPTX, PPT,
              ODT, EPUB
  Text      : XML, HTML, JSON, CSV
  Archives  : ZIP, RAR, 7zip, gzip, bzip2, xz, zlib, Zstd,
              LZMA, ISO
  Email     : EML, MSG (Outlook), MBOX, PST
  Executables: PE/EXE, ELF, Mach-O, Shell scripts
  Database  : SQLite3, MySQL dump
  Network   : PCAP, PCAPNG
  Crypto    : LUKS, PEM, GPG/PGP
  Disk      : VMDK, QCOW2, VHD
  Firmware  : U-Boot, SquashFS, JFFS2, CramFS
  Font      : TTF, OTF, WOFF
  Other     : SWF, Java .class, Android DEX, Torrent

------------------------------------------------------------
  STEGANOGRAPHY TOOL (steg_tool.py)
------------------------------------------------------------

A companion script for embedding and extracting LSB
messages is included separately as steg_tool.py.

  Embed a message:
    python steg_tool.py embed carrier.png output.png "msg"

  Extract a message:
    python steg_tool.py extract output.png

  Requires: pip install Pillow

------------------------------------------------------------
  TROUBLESHOOTING
------------------------------------------------------------

App crashes immediately on launch:
  - Run from command line to see the error:
      python forensix.py
  - Check forensix_crash.log next to the EXE

"Python not found" in the installer:
  - Reinstall Python from https://python.org
  - Make sure to check "Add Python to PATH"

Entropy graph not showing:
  - matplotlib may have failed to install
  - Run: python -m pip install matplotlib

LSB analysis not running on images:
  - Pillow may not be installed
  - Run: python -m pip install Pillow

Metadata tab shows limited info:
  - Install exiftool for full EXIF data:
      https://exiftool.org
  - On Windows, add exiftool.exe to your PATH

Analysis is slow on large files:
  - Files over 500 MB may take 30-60 seconds
  - The UI remains responsive during analysis
  - Progress is shown in the animation overlay

------------------------------------------------------------
  FILES IN THIS PACKAGE
------------------------------------------------------------

  forensix.py          Main application (run this)
  install_and_run.bat  Installs dependencies and launches
  build_exe.bat        Builds a standalone Forensix.exe
  README.txt           This file

------------------------------------------------------------
  CREATOR
------------------------------------------------------------

  FORENSIX was created by Daniel Ben Yehuda.

  LinkedIn : www.linkedin.com/in/daniel-by
  Email    : benyehudad@protonmail.com

  Feel free to reach out for questions, feedback,
  or collaboration.

------------------------------------------------------------
  LICENSE
------------------------------------------------------------

FORENSIX is provided for educational and legitimate
digital forensics use only. The user is responsible
for ensuring lawful use in their jurisdiction.

============================================================
