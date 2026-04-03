#!/usr/bin/env python3
"""
FORENSIX - Digital Forensics Analysis Tool
Requires: PyQt6, matplotlib, Pillow
Install:  pip install PyQt6 matplotlib Pillow
"""

import sys, os, math, hashlib, subprocess, json, re
from pathlib import Path
from datetime import datetime

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QLabel, QPushButton, QFileDialog, QTextEdit,
        QTreeWidget, QTreeWidgetItem, QProgressBar, QSplitter,
        QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
        QLineEdit, QSpinBox, QCheckBox, QComboBox, QGroupBox,
        QMessageBox, QSizePolicy
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QColor
except ImportError:
    print("ERROR: PyQt6 not installed.\nRun: pip install PyQt6")
    sys.exit(1)

HAS_MPL = False
try:
    import matplotlib
    matplotlib.use("QtAgg")
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import numpy as np
    HAS_MPL = True
except Exception:
    pass

HAS_PIL = False
try:
    from PIL import Image
    HAS_PIL = True
except Exception:
    pass

# ═══════════════════════════════════════════════════════════════════════════
# THEME
# ═══════════════════════════════════════════════════════════════════════════
DARK   = "#0D0F14"
MID    = "#151820"
PANEL  = "#1C2030"
BORDER = "#252A3A"
ACCENT = "#00E5FF"
GREEN  = "#00FF9D"
AMBER  = "#FFB300"
RED    = "#FF4444"
DIM    = "#4A5270"
TEXT   = "#C8D0E8"
BRIGHT = "#FFFFFF"

QSS = f"""
QMainWindow, QWidget {{ background:{DARK}; color:{TEXT}; font-family:'Consolas','Courier New',monospace; font-size:13px; }}
QTabWidget::pane {{ border:1px solid {BORDER}; background:{PANEL}; }}
QTabBar::tab {{ background:{MID}; color:{DIM}; padding:10px 22px; border:1px solid {BORDER}; border-bottom:none; font-size:12px; letter-spacing:1px; }}
QTabBar::tab:selected {{ background:{PANEL}; color:{ACCENT}; border-top:2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color:{TEXT}; }}
QPushButton {{ background:{MID}; color:{ACCENT}; border:1px solid {ACCENT}; padding:8px 20px; border-radius:3px; font-size:12px; letter-spacing:1px; }}
QPushButton:hover {{ background:{ACCENT}; color:{DARK}; }}
QPushButton:disabled {{ color:{DIM}; border-color:{DIM}; background:{MID}; }}
QPushButton#primary {{ background:{ACCENT}; color:{DARK}; font-weight:bold; }}
QPushButton#primary:hover {{ background:#33EEFF; }}
QPushButton#danger {{ border-color:{RED}; color:{RED}; }}
QPushButton#danger:hover {{ background:{RED}; color:{BRIGHT}; }}
QPushButton#success {{ border-color:{GREEN}; color:{GREEN}; }}
QPushButton#success:hover {{ background:{GREEN}; color:{DARK}; }}
QLineEdit, QTextEdit, QSpinBox, QComboBox {{ background:{MID}; color:{TEXT}; border:1px solid {BORDER}; padding:6px; border-radius:2px; }}
QLineEdit:focus, QTextEdit:focus {{ border-color:{ACCENT}; }}
QTreeWidget, QTableWidget {{ background:{MID}; color:{TEXT}; border:1px solid {BORDER}; gridline-color:{BORDER}; alternate-background-color:{PANEL}; }}
QTreeWidget::item:selected, QTableWidget::item:selected {{ background:#1A2A3A; color:{ACCENT}; }}
QHeaderView::section {{ background:{PANEL}; color:{DIM}; border:1px solid {BORDER}; padding:6px; font-size:11px; letter-spacing:1px; }}
QScrollBar:vertical {{ background:{MID}; width:8px; }}
QScrollBar::handle:vertical {{ background:{BORDER}; border-radius:4px; }}
QScrollBar::handle:vertical:hover {{ background:{DIM}; }}
QProgressBar {{ background:{MID}; border:1px solid {BORDER}; border-radius:2px; text-align:center; color:{TEXT}; height:18px; }}
QProgressBar::chunk {{ background:{ACCENT}; }}
QGroupBox {{ border:1px solid {BORDER}; border-radius:3px; margin-top:10px; padding-top:10px; color:{DIM}; font-size:11px; letter-spacing:1px; }}
QGroupBox::title {{ subcontrol-origin:margin; left:10px; color:{DIM}; }}
QCheckBox {{ color:{TEXT}; spacing:8px; }}
QCheckBox::indicator {{ width:14px; height:14px; border:1px solid {BORDER}; background:{MID}; }}
QCheckBox::indicator:checked {{ background:{ACCENT}; border-color:{ACCENT}; }}
QSplitter::handle {{ background:{BORDER}; width:2px; }}
"""

# ═══════════════════════════════════════════════════════════════════════════
# MAGIC SIGNATURES
# Format: (name, hex_magic, offset, extension, category, min_size, max_size_multiplier)
# min_size: minimum plausible size in bytes (0 = no minimum)
# max_size_multiplier: max size as fraction of file (1.0 = whole file, 0 = no limit)
# ═══════════════════════════════════════════════════════════════════════════
MAGIC_SIGNATURES = [
    # ── Images ──────────────────────────────────────────────────────────────
    ("JPEG",              "FFD8FF",                   0, ".jpg",    "Image",      1024,      0),
    ("PNG",               "89504E470D0A1A0A",          0, ".png",    "Image",      67,        0),
    ("GIF87a",            "474946383761",              0, ".gif",    "Image",      35,        0),
    ("GIF89a",            "474946383961",              0, ".gif",    "Image",      35,        0),
    ("BMP",               "424D",                      0, ".bmp",    "Image",      54,        0),
    ("TIFF LE",           "49492A00",                  0, ".tif",    "Image",      8,         0),
    ("TIFF BE",           "4D4D002A",                  0, ".tif",    "Image",      8,         0),
    ("WebP",              "52494646",                  0, ".webp",   "Image",      30,        0),
    ("ICO",               "00000100",                  0, ".ico",    "Image",      6,         0),
    ("PSD",               "38425053",                  0, ".psd",    "Image",      26,        0),
    # ── Documents ───────────────────────────────────────────────────────────
    ("PDF",               "255044462D",                0, ".pdf",    "Document",   1024,      0),
    ("RTF",               "7B5C72746631",              0, ".rtf",    "Document",   10,        0),
    ("DOCX/XLSX/PPTX",    "504B0304",                  0, ".docx",   "Document",   2048,      0),
    ("DOC",               "D0CF11E0A1B11AE1",          0, ".doc",    "Document",   512,       0),
    ("XLS",               "D0CF11E0A1B11AE1",          0, ".xls",    "Document",   512,       0),
    ("PPT",               "D0CF11E0A1B11AE1",          0, ".ppt",    "Document",   512,       0),
    ("ODT",               "504B0304",                  0, ".odt",    "Document",   2048,      0),
    ("EPUB",              "504B0304",                  0, ".epub",   "Document",   2048,      0),
    # ── Plain text ──────────────────────────────────────────────────────────
    ("XML",               "3C3F786D6C",                0, ".xml",    "Text",       10,        0),
    ("HTML",              "3C68746D6C",                0, ".html",   "Text",       10,        0),
    ("HTML2",             "3C21444F43",                0, ".html",   "Text",       10,        0),
    ("JSON",              "7B0A",                      0, ".json",   "Text",       2,         0),
    ("CSV (BOM)",         "EFBBBF",                    0, ".csv",    "Text",       3,         0),
    # ── Archives ────────────────────────────────────────────────────────────
    ("ZIP",               "504B0304",                  0, ".zip",    "Archive",    22,        0),
    ("ZIP empty",         "504B0506",                  0, ".zip",    "Archive",    22,        0),
    ("RAR4",              "526172211A0700",             0, ".rar",    "Archive",    7,         0),
    ("RAR5",              "526172211A070100",           0, ".rar",    "Archive",    8,         0),
    ("7zip",              "377ABCAF271C",               0, ".7z",     "Archive",    32,        0),
    ("gzip",              "1F8B",                       0, ".gz",     "Archive",    18,        0),
    ("bzip2",             "425A68",                     0, ".bz2",    "Archive",    14,        0),
    ("xz",                "FD377A585A00",               0, ".xz",     "Archive",    32,        0),
    ("zlib",              "789C",                       0, ".zlib",   "Archive",    2,         0),
    ("Zstd",              "28B52FFD",                   0, ".zst",    "Archive",    4,         0),
    ("LZMA",              "5D000000",                   0, ".lzma",   "Archive",    13,        0),
    ("ISO",               "4344303031",             32769, ".iso",    "Archive",    32768,     0),
    # ── Video ───────────────────────────────────────────────────────────────
    ("MP4/ftyp",          "66747970",                   4, ".mp4",    "Video",      1048576,   0),
    ("MP4 (ftypisom)",    "6674797069736F6D",           4, ".mp4",    "Video",      1048576,   0),
    ("MP4 (ftypmp42)",    "667479706D703432",           4, ".mp4",    "Video",      1048576,   0),
    ("AVI",               "41564920",                   8, ".avi",    "Video",      1048576,   0),
    ("MKV",               "1A45DFA3",                   0, ".mkv",    "Video",      1048576,   0),
    ("MOV",               "6674797071742020",           4, ".mov",    "Video",      1048576,   0),
    ("WMV/ASF",           "3026B2758E66CF11",           0, ".wmv",    "Video",      1048576,   0),
    ("FLV",               "464C5601",                   0, ".flv",    "Video",      512,       0),
    ("MPEG",              "000001BA",                   0, ".mpg",    "Video",      512,       0),
    ("MPEG2",             "000001B3",                   0, ".mpg",    "Video",      512,       0),
    ("WebM",              "1A45DFA3",                   0, ".webm",   "Video",      1048576,   0),
    ("3GP",               "667479703367",               4, ".3gp",    "Video",      512,       0),
    # ── Audio ───────────────────────────────────────────────────────────────
    ("MP3 ID3",           "494433",                     0, ".mp3",    "Audio",      128,       0),
    ("MP3 frame",         "FFFB",                       0, ".mp3",    "Audio",      128,       0),
    ("MP3 frame2",        "FFF3",                       0, ".mp3",    "Audio",      128,       0),
    ("MP3 frame3",        "FFF2",                       0, ".mp3",    "Audio",      128,       0),
    ("FLAC",              "664C6143",                   0, ".flac",   "Audio",      128,       0),
    ("WAV",               "57415645",                  8, ".wav",    "Audio",      44,        0),
    ("OGG",               "4F676753",                   0, ".ogg",    "Audio",      27,        0),
    ("AAC ADTS",          "FFF1",                       0, ".aac",    "Audio",      7,         0),
    ("AAC ADTS2",         "FFF9",                       0, ".aac",    "Audio",      7,         0),
    ("M4A",               "667479704D344120",           4, ".m4a",    "Audio",      512,       0),
    ("AIFF",              "464F524D",                   0, ".aiff",   "Audio",      54,        0),
    ("WMA",               "3026B2758E66CF11",           0, ".wma",    "Audio",      512,       0),
    ("Opus",              "4F707573486561",             28, ".opus",   "Audio",      19,        0),
    ("Speex",             "5370656578202020",           28, ".spx",    "Audio",      80,        0),
    ("AMR",               "2321414D52",                 0, ".amr",    "Audio",      6,         0),
    ("MIDI",              "4D546864",                   0, ".mid",    "Audio",      14,        0),
    # ── Email ───────────────────────────────────────────────────────────────
    ("EML (From)",        "46726F6D20",                 0, ".eml",    "Email",      10,        0),
    ("EML (Return-Path)", "52657475726E2D50617468",     0, ".eml",    "Email",      10,        0),
    ("EML (MIME)",        "4D494D452D56657273696F6E",   0, ".eml",    "Email",      10,        0),
    ("EML (Received)",    "52656365697665643A20",       0, ".eml",    "Email",      10,        0),
    ("MSG (Outlook)",     "D0CF11E0A1B11AE1",           0, ".msg",    "Email",      512,       0),
    ("MBOX",              "46726F6D20",                 0, ".mbox",   "Email",      10,        0),
    ("PST",               "2142444E",                   0, ".pst",    "Email",      512,       0),
    # ── Executables ─────────────────────────────────────────────────────────
    ("PE/EXE",            "4D5A",                       0, ".exe",    "Executable", 64,        0),
    ("ELF",               "7F454C46",                   0, ".elf",    "Executable", 52,        0),
    ("Mach-O 32",         "FEEDFACE",                   0, ".macho",  "Executable", 28,        0),
    ("Mach-O 64",         "FEEDFACF",                   0, ".macho",  "Executable", 32,        0),
    ("Mach-O FAT",        "CAFEBABE",                   0, ".macho",  "Executable", 8,         0),
    ("Script sh",         "23212F62696E2F73",           0, ".sh",     "Executable", 4,         0),
    ("Script py",         "23212F7573722F",             0, ".py",     "Executable", 4,         0),
    # ── Database ────────────────────────────────────────────────────────────
    ("SQLite3",           "53514C69746520666F726D6174203300", 0, ".db", "Database", 100,      0),
    ("MySQL dump",        "2D2D204D7953514C",           0, ".sql",    "Database",   10,        0),
    # ── Network / Forensics ─────────────────────────────────────────────────
    ("PCAP",              "D4C3B2A1",                   0, ".pcap",   "Network",    24,        0),
    ("PCAP BE",           "A1B2C3D4",                   0, ".pcap",   "Network",    24,        0),
    ("PCAPNG",            "0A0D0D0A",                   0, ".pcapng", "Network",    28,        0),
    # ── Crypto / Security ───────────────────────────────────────────────────
    ("LUKS",              "4C554B53BABE",               0, ".img",    "Crypto",     4096,      0),
    ("PEM cert",          "2D2D2D2D2D424547494E",       0, ".pem",    "Crypto",     10,        0),
    ("GPG/PGP",           "99",                         0, ".gpg",    "Crypto",     1,         0),
    ("GPG ASCII",         "2D2D2D2D2D424547494E20504750", 0, ".asc",  "Crypto",     10,        0),
    # ── Disk / Firmware ─────────────────────────────────────────────────────
    ("VMware VMDK",       "4B444D56",                   0, ".vmdk",   "Disk",       512,       0),
    ("QEMU QCOW2",        "514649FB",                   0, ".qcow2",  "Disk",       104,       0),
    ("VHD",               "636F6E6563746978",           0, ".vhd",    "Disk",       512,       0),
    ("SquashFS",          "73717368",                   0, ".sqfs",   "Filesystem", 96,        0),
    ("JFFS2 LE",          "8519",                       0, ".jffs2",  "Filesystem", 12,        0),
    ("CramFS",            "28CD3D45",                   0, ".cramfs", "Filesystem", 76,        0),
    ("U-Boot",            "27051956",                   0, ".uboot",  "Firmware",   64,        0),
    # ── Font ────────────────────────────────────────────────────────────────
    ("TrueType",          "0001000000",                 0, ".ttf",    "Font",       12,        0),
    ("OpenType",          "4F54544F",                   0, ".otf",    "Font",       12,        0),
    ("WOFF",              "774F4646",                   0, ".woff",   "Font",       44,        0),
    # ── Other ───────────────────────────────────────────────────────────────
    ("SWF",               "465753",                     0, ".swf",    "Flash",      8,         0),
    ("SWF compressed",    "435753",                     0, ".swf",    "Flash",      8,         0),
    ("Java class",        "CAFEBABE",                   0, ".class",  "Java",       32,        0),
    ("DEX",               "6465780A",                   0, ".dex",    "Android",    112,       0),
    ("Torrent",           "6431303A",                   0, ".torrent","Other",      20,        0),
    # ── FORENSIX custom embed markers ───────────────────────────────────────
    ("FORENSIX WAV embed",   "3C3C464F52454E5349585F57415656",  0, ".wav", "Audio",    0, 0),
    ("FORENSIX PNG embed",   "3C3C464F52454E5349585F504E47",    0, ".png", "Image",    0, 0),
    ("FORENSIX TXT embed",   "3C3C464F52454E5349585F545854",    0, ".txt", "Text",     0, 0),
    ("FORENSIX Script embed","3C3C464F52454E5349585F4D414C",    0, ".py",  "Executable",0,0),
    ("FORENSIX PDF embed",   "3C3C464F52454E5349585F504446",    0, ".pdf", "Document", 0, 0),
    ("FORENSIX DOCX embed",  "3C3C464F52454E5349585F444F43",    0, ".docx","Document", 0, 0),
]

# ═══════════════════════════════════════════════════════════════════════════
# ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════
class AnalysisEngine:
    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.data = b""

    def load(self):
        with open(self.filepath, "rb") as f:
            self.data = f.read()

    def compute_hashes(self):
        import zlib
        d = self.data
        return {
            "MD5":    hashlib.md5(d).hexdigest(),
            "SHA1":   hashlib.sha1(d).hexdigest(),
            "SHA256": hashlib.sha256(d).hexdigest(),
            "SHA512": hashlib.sha512(d).hexdigest(),
            "CRC32":  f"{zlib.crc32(d) & 0xFFFFFFFF:08X}",
            "Size":   f"{len(d):,} bytes ({len(d)/1024/1024:.2f} MB)",
        }

    def get_metadata(self):
        meta = {}
        p, stat = self.filepath, self.filepath.stat()
        meta["File Info"] = {
            "Filename":   p.name,
            "Extension":  p.suffix,
            "Size":       f"{stat.st_size:,} bytes",
            "Modified":   datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "Accessed":   datetime.fromtimestamp(stat.st_atime).isoformat(),
            "Created":    datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "Permissions":oct(stat.st_mode),
        }
        try:
            out = subprocess.check_output(["file", "-b", str(p)], text=True, timeout=5,
                                          stderr=subprocess.DEVNULL).strip()
            meta["File Type"] = {"Detection": out}
        except Exception:
            pass
        try:
            out = subprocess.check_output(["exiftool", "-j", str(p)], text=True, timeout=10,
                                          stderr=subprocess.DEVNULL)
            exif = json.loads(out)[0]
            exif.pop("SourceFile", None)
            meta["EXIF / ExifTool"] = exif
        except Exception:
            pass
        printable = re.findall(rb'[ -~]{4,}', self.data)
        meta["Strings Summary"] = {
            "Printable strings (>=4 chars)": str(len(printable)),
            "Longest string": str(max((len(s) for s in printable), default=0)) + " chars",
        }
        return meta

    def extract_strings(self, min_len=4):
        results = []
        pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
        for m in re.finditer(pattern, self.data):
            results.append((m.start(), m.group().decode("ascii", errors="replace")))
        u16 = re.findall(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}', self.data)
        for s in u16:
            results.append((-1, s.decode("utf-16-le", errors="replace")))
        return results

    def _shannon(self, data):
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        e = 0.0
        n = len(data)
        for c in counts:
            if c:
                p = c / n
                e -= p * math.log2(p)
        return e / 8.0

    def compute_entropy_blocks(self, block_size=4096):
        results = []
        for i in range(0, len(self.data), block_size):
            chunk = self.data[i:i+block_size]
            if chunk:
                results.append((i, self._shannon(chunk)))
        return results

    def find_entropy_edges(self, blocks, threshold=0.08):
        edges = []
        for i in range(1, len(blocks)):
            delta = blocks[i][1] - blocks[i-1][1]
            if abs(delta) >= threshold:
                edges.append((blocks[i][0],
                               "Rising" if delta > 0 else "Falling",
                               blocks[i][1]))
        return edges

    def scan_magic(self, extra_sigs=None):
        sigs = list(MAGIC_SIGNATURES)
        if extra_sigs:
            sigs.extend(extra_sigs)

        file_size = len(self.data)
        findings  = []

        # ── Locate PNG internal region to suppress false positives ────
        png_data_start = -1
        png_data_end   = -1
        if self.data[:8] == bytes.fromhex("89504E470D0A1A0A"):
            idat = self.data.find(b'IDAT')
            # Use the FIRST IEND (not rfind) so appended data after PNG
            # doesn't extend the suppression window into embedded files.
            # Search only within the first 95% of the file to avoid
            # catching IEND markers inside appended embedded PNGs.
            search_limit = int(len(self.data) * 0.95)
            iend = self.data.find(b'IEND', 0, search_limit)
            if idat != -1 and iend != -1:
                png_data_start = idat
                png_data_end   = iend + 12

        # ── RIFF subtype map ──────────────────────────────────────────
        RIFF_SUBTYPES = {
            b'WAVE': ("WAV",  ".wav",  "Audio",  44),
            b'WEBP': ("WebP", ".webp", "Image",  30),
            b'AVI ': ("AVI",  ".avi",  "Video",  1048576),
        }
        RIFF_GENERIC_NAMES = {"WebP", "WAV", "AVI"}

        for entry in sigs:
            if len(entry) == 7:
                name, hex_sig, offset_check, ext, category, min_size, _ = entry
            else:
                name, hex_sig, offset_check, ext, category = entry[:5]
                min_size = 0

            # RIFF family handled separately below
            if hex_sig.upper() == "52494646" and name in RIFF_GENERIC_NAMES:
                continue

            try:
                sig = bytes.fromhex(hex_sig)
            except ValueError:
                continue

            search_start = 0
            while True:
                idx = self.data.find(sig, search_start)
                if idx == -1:
                    break

                # Suppress hits inside PNG pixel/compressed data region
                in_png_body = (png_data_start != -1
                               and png_data_start < idx < png_data_end
                               and name not in ("PNG", "zlib", "IDAT"))
                if in_png_body:
                    search_start = idx + 1
                    continue

                remaining  = file_size - idx
                plausible  = remaining >= min_size if min_size > 0 else True
                size_est   = self._estimate_size(idx, self.data, ext)
                confidence = self._confidence(idx, remaining, min_size,
                                              size_est, file_size, name)
                hex_preview = self.data[idx:idx+32].hex(" ").upper()

                findings.append({
                    "offset":        idx,
                    "hex_offset":    f"0x{idx:X}",
                    "name":          name,
                    "extension":     ext,
                    "category":      category,
                    "magic":         hex_sig[:16],
                    "size_estimate": size_est,
                    "min_size":      min_size,
                    "plausible":     plausible,
                    "confidence":    confidence,
                    "hex_preview":   hex_preview,
                })

                search_start = idx + 1
                if search_start >= file_size:
                    break

        # ── RIFF family: discriminate by subtype bytes 8-11 ──────────
        search_start = 0
        while True:
            idx = self.data.find(b'RIFF', search_start)
            if idx == -1:
                break
            in_png_body = (png_data_start != -1
                           and png_data_start < idx < png_data_end)
            if idx + 12 <= file_size and not in_png_body:
                subtype = self.data[idx+8:idx+12]
                if subtype in RIFF_SUBTYPES:
                    name, ext, category, min_size = RIFF_SUBTYPES[subtype]
                    remaining  = file_size - idx
                    plausible  = remaining >= min_size
                    size_est   = self._estimate_size(idx, self.data, ext)
                    confidence = self._confidence(idx, remaining, min_size,
                                                  size_est, file_size, name)
                    findings.append({
                        "offset":        idx,
                        "hex_offset":    f"0x{idx:X}",
                        "name":          name,
                        "extension":     ext,
                        "category":      category,
                        "magic":         "52494646",
                        "size_estimate": size_est,
                        "min_size":      min_size,
                        "plausible":     plausible,
                        "confidence":    confidence,
                        "hex_preview":   self.data[idx:idx+32].hex(" ").upper(),
                    })
            search_start = idx + 1
            if search_start >= file_size:
                break

        findings.sort(key=lambda x: x["offset"])

        # Collapse duplicates that are CLOSE together (within 512KB)
        # Far-apart hits of the same type are kept — they are different files
        COLLAPSE_WINDOW = 524288  # 512 KB
        collapsed = []
        for f in findings:
            merged = False
            for c in collapsed:
                if c["name"] == f["name"] and abs(f["offset"] - c["offset"]) < COLLAPSE_WINDOW:
                    c["dup_count"] = c.get("dup_count", 0) + 1
                    merged = True
                    break
            if not merged:
                collapsed.append(f)

        # Deduplicate very close offsets (within 16 bytes)
        deduped, last = [], -9999
        for f in collapsed:
            if f["offset"] - last > 16:
                deduped.append(f)
                last = f["offset"]

        return deduped

    def _confidence(self, offset, remaining, min_size, size_est, file_size, name, in_png_body=False):
        score = 0
        if in_png_body:
            return "LOW"
        # At start of file = high confidence
        if offset < 512:
            score += 3
        elif offset < 4096:
            score += 1
        # Enough data remains for minimum size
        if min_size > 0 and remaining >= min_size:
            score += 2
        elif min_size > 0 and remaining < min_size:
            score -= 3
        # Size estimate is plausible
        if isinstance(size_est, int) and 0 < size_est <= remaining:
            score += 1
        # Known reliable signatures
        reliable = {"JPEG", "PNG", "GIF87a", "GIF89a", "PDF", "ZIP", "RAR4", "RAR5",
                    "7zip", "MP4/ftyp", "ELF", "PE/EXE", "SQLite3", "FLAC", "OGG",
                    "WAV", "MP3 ID3", "MKV"}
        if name in reliable:
            score += 2
        # FORENSIX embed markers are always real
        if name.startswith("FORENSIX "):
            score += 3

        if score >= 5:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        else:
            return "LOW"

    def _estimate_size(self, offset, data, ext):
        remaining = len(data) - offset
        if ext == ".png":
            end = data.find(b'IEND', offset)
            if end != -1:
                return end + 8 - offset
        if ext in (".zip", ".docx", ".odt", ".epub"):
            end = data.find(b'PK\x05\x06', offset)
            if end != -1 and end + 22 < len(data):
                return end + 22 - offset
        if ext == ".jpg":
            end = data.find(b'\xFF\xD9', offset + 2)
            if end != -1:
                return end + 2 - offset
        return remaining

    def check_anomalies(self):
        results = []
        data, size = self.data, len(self.data)

        if data.endswith(b'\x00' * 512):
            null_start = len(data.rstrip(b'\x00'))
            results.append({"type": "Null padding", "severity": "LOW",
                             "offset": f"0x{null_start:X}",
                             "detail": f"{size - null_start:,} null bytes at end of file"})

        jpeg_eoi = data.rfind(b'\xFF\xD9')
        if jpeg_eoi != -1 and jpeg_eoi < size - 2:
            extra = size - jpeg_eoi - 2
            if extra > 16:
                results.append({"type": "JPEG - data after EOI", "severity": "HIGH",
                                 "offset": f"0x{jpeg_eoi+2:X}",
                                 "detail": f"{extra:,} bytes after JPEG End-Of-Image marker"})

        png_iend = data.find(b'IEND\xAE\x42\x60\x82')
        if png_iend != -1 and png_iend + 8 < size:
            extra = size - png_iend - 8
            if extra > 0:
                results.append({"type": "PNG - data after IEND", "severity": "HIGH",
                                 "offset": f"0x{png_iend+8:X}",
                                 "detail": f"{extra:,} bytes after PNG IEND chunk"})

        if HAS_PIL and self.filepath.suffix.lower() in ('.png', '.bmp', '.tif', '.tiff', '.jpg', '.jpeg'):
            lsb = self._check_lsb()
            if lsb:
                results.append(lsb)

        blocks = self.compute_entropy_blocks(2048)
        if blocks:
            max_e = max(b[1] for b in blocks)
            avg_e = sum(b[1] for b in blocks) / len(blocks)
            if max_e > 0.99 and avg_e < 0.85:
                results.append({"type": "Entropy anomaly", "severity": "MEDIUM",
                                 "offset": "multiple",
                                 "detail": f"Max entropy {max_e:.4f} well above average {avg_e:.4f}"})

        last_pk = data.rfind(b'PK')
        if last_pk > 1024:
            results.append({"type": "Possible appended ZIP", "severity": "MEDIUM",
                             "offset": f"0x{last_pk:X}",
                             "detail": "PK signature found near end of file"})

        return results

    def _check_lsb(self):
        """Quick check for anomalies tab — returns single finding or None."""
        result = self.analyze_lsb_full()
        if result and result["verdict"] in ("DETECTED", "SUSPECTED"):
            return {
                "type": f"LSB Steganography ({result['verdict']})",
                "severity": "HIGH" if result["verdict"] == "DETECTED" else "MEDIUM",
                "offset": "pixel data",
                "detail": result["summary"],
            }
        return None

    def analyze_lsb_full(self):
        """Full LSB analysis — numpy-accelerated, returns rich dict for Steganography tab."""
        if not HAS_PIL:
            return None
        ext = self.filepath.suffix.lower()
        if ext not in ('.png', '.bmp', '.tif', '.tiff', '.jpg', '.jpeg'):
            return {"verdict": "NOT_IMAGE", "summary": "Not an image file.", "details": {}}
        try:
            img = Image.open(self.filepath).convert("RGB")
        except Exception as e:
            return {"verdict": "ERROR", "summary": str(e), "details": {}}

        import tempfile
        w, h = img.size
        total_pixels = w * h

        # ── Use numpy if available, else fall back to PIL ─────────────
        try:
            import numpy as np
            arr = np.array(img)          # shape (H, W, 3), dtype uint8
            HAS_NP = True
        except ImportError:
            HAS_NP = False

        # ── 1. LSB ratio per channel (numpy: ~0.005s) ─────────────────
        lsb_ratios = []
        if HAS_NP:
            for ch in range(3):
                lsb_ratios.append(float((arr[:,:,ch] & 1).mean()))
        else:
            pixels = list(img.getdata())
            for ch in range(3):
                lsb_ratios.append(sum((p[ch] & 1) for p in pixels) / total_pixels)

        # ── 2. Chi-square test per channel (numpy: ~0.35s) ────────────
        chi_scores = []
        if HAS_NP:
            for ch in range(3):
                vals = arr[:,:,ch].ravel()
                chi, pairs = 0.0, 0
                for k in range(128):
                    n0 = int(np.sum(vals == 2*k))
                    n1 = int(np.sum(vals == 2*k+1))
                    total = n0 + n1
                    if total > 4:
                        expected = total / 2
                        chi += ((n0-expected)**2/expected) + ((n1-expected)**2/expected)
                        pairs += 1
                chi_scores.append(chi / pairs if pairs > 0 else 0)
        else:
            from collections import Counter
            pixels = list(img.getdata())
            for ch in range(3):
                vals_list = [p[ch] for p in pixels]
                counts = Counter(vals_list)
                chi, pairs = 0.0, 0
                for k in range(128):
                    n0 = counts.get(2*k, 0)
                    n1 = counts.get(2*k+1, 0)
                    total = n0 + n1
                    if total > 4:
                        expected = total / 2
                        chi += ((n0-expected)**2/expected) + ((n1-expected)**2/expected)
                        pairs += 1
                chi_scores.append(chi / pairs if pairs > 0 else 0)

        avg_chi      = sum(chi_scores) / 3
        chi_variance = sum((c - avg_chi)**2 for c in chi_scores) / 3

        # ── 3. Auto-extract LSB bytes (numpy: ~0.004s) ────────────────
        DELIMITER = b'<<FORENSIX_END>>'
        if HAS_NP:
            lsb_flat = (arr & 1).ravel()
            n = (len(lsb_flat) // 8) * 8
            weights  = np.array([128,64,32,16,8,4,2,1], dtype=np.uint8)
            raw_bytes = np.dot(lsb_flat[:n].reshape(-1,8), weights).astype(np.uint8).tobytes()
        else:
            pixels = list(img.getdata())
            bits = ''
            for p in pixels:
                bits += str(p[0]&1) + str(p[1]&1) + str(p[2]&1)
            raw_bytes = bytes(int(bits[i:i+8],2) for i in range(0, len(bits)-7, 8))

        extracted_text  = None
        extracted_magic = None
        extracted_bytes = None

        end = raw_bytes.find(DELIMITER)
        if end != -1 and end < 100000:
            try:
                extracted_text = raw_bytes[:end].decode("utf-8", errors="strict")
            except Exception:
                extracted_text = raw_bytes[:end].decode("latin-1", errors="replace")
            extracted_bytes = raw_bytes[:end]

        first_bytes = raw_bytes[:16]
        MAGIC_CHECKS = [
            (b'\xFF\xD8\xFF', "JPEG image"),
            (b'\x89PNG',        "PNG image"),
            (b'PK\x03\x04',     "ZIP / DOCX / XLSX"),
            (b'%PDF',           "PDF document"),
            (b'MZ',             "Windows Executable"),
            (b'\x7fELF',        "ELF Executable"),
            (b'ID3',            "MP3 audio"),
            (b'RIFF',           "WAV / WebP"),
            (b'fLaC',           "FLAC audio"),
            (b'OggS',           "OGG audio"),
            (b'\x1f\x8b',       "GZIP archive"),
            (b'Rar!',           "RAR archive"),
            (b'7z\xbc\xaf',     "7-Zip archive"),
            (b'SQLite',         "SQLite database"),
        ]
        for magic, label in MAGIC_CHECKS:
            if first_bytes[:len(magic)] == magic:
                extracted_magic = label
                break

        # ── 4. Noise map (numpy: ~0.006s) ─────────────────────────────
        if HAS_NP:
            noise_arr = ((arr & 1) * 255).astype(np.uint8)
            noise_img = Image.fromarray(noise_arr, 'RGB')
        else:
            pixels = list(img.getdata())
            noise_pixels = [((p[0]&1)*255, (p[1]&1)*255, (p[2]&1)*255) for p in pixels]
            noise_img = Image.new("RGB", (w, h))
            noise_img.putdata(noise_pixels)

        noise_path = os.path.join(tempfile.gettempdir(), "forensix_lsb_noise.png")
        noise_img.save(noise_path)

        # ── 5. Verdict ────────────────────────────────────────────────
        lsb_avg          = sum(lsb_ratios) / 3
        suspicious_ratio = all(0.47 < r < 0.53 for r in lsb_ratios)
        suspicious_chi   = chi_variance < 500
        has_extraction   = extracted_text is not None or extracted_magic is not None

        if has_extraction:
            verdict = "DETECTED"
        elif suspicious_ratio and suspicious_chi:
            verdict = "DETECTED"
        elif suspicious_ratio or suspicious_chi:
            verdict = "SUSPECTED"
        else:
            verdict = "CLEAN"

        summary_parts = []
        if suspicious_ratio:
            summary_parts.append(f"LSB ratios uniform ({lsb_avg:.4f})")
        if suspicious_chi:
            summary_parts.append(f"Chi-square variance low ({chi_variance:.1f})")
        if extracted_text:
            summary_parts.append(f"Hidden text extracted: '{extracted_text[:60]}'")
        if extracted_magic:
            summary_parts.append(f"Embedded file detected: {extracted_magic}")
        summary = " | ".join(summary_parts) if summary_parts else "No LSB anomalies found."

        return {
            "verdict":        verdict,
            "summary":        summary,
            "lsb_ratios":     lsb_ratios,
            "chi_scores":     chi_scores,
            "chi_variance":   chi_variance,
            "avg_chi":        avg_chi,
            "extracted_text": extracted_text,
            "extracted_magic":extracted_magic,
            "extracted_bytes":extracted_bytes,
            "noise_path":     noise_path,
            "image_size":     (w, h),
            "total_pixels":   total_pixels,
            "capacity_bytes": (total_pixels * 3) // 8,
            "numpy_used":     HAS_NP,
        }


# ═══════════════════════════════════════════════════════════════════════════
# WORKER THREAD
# ═══════════════════════════════════════════════════════════════════════════
class AnalysisWorker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error    = pyqtSignal(str)

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    def run(self):
        import traceback as _tb
        try:
            eng = AnalysisEngine(self.filepath)
            self.progress.emit(5,  "Loading file...")
            eng.load()
            self.progress.emit(15, "Computing hashes...")
            hashes = eng.compute_hashes()
            self.progress.emit(25, "Extracting metadata...")
            try:    metadata = eng.get_metadata()
            except: metadata = {"Error": {"detail": _tb.format_exc()}}
            self.progress.emit(40, "Extracting strings...")
            try:    strings = eng.extract_strings()
            except: strings = []
            self.progress.emit(55, "Computing entropy...")
            try:
                entropy_blocks = eng.compute_entropy_blocks(4096)
                entropy_edges  = eng.find_entropy_edges(entropy_blocks)
            except:
                entropy_blocks, entropy_edges = [], []
            self.progress.emit(70, "Scanning magic signatures...")
            try:    magic_hits = eng.scan_magic()
            except: magic_hits = []
            self.progress.emit(85, "Checking anomalies...")
            try:    anomalies = eng.check_anomalies()
            except: anomalies = []
            self.progress.emit(92, "LSB steganography analysis...")
            try:    lsb_analysis = eng.analyze_lsb_full()
            except: lsb_analysis = None
            self.progress.emit(100, "Done.")
            self.finished.emit({
                "filepath":       self.filepath,
                "hashes":         hashes,
                "metadata":       metadata,
                "strings":        strings,
                "entropy_blocks": entropy_blocks,
                "entropy_edges":  entropy_edges,
                "magic_hits":     magic_hits,
                "anomalies":      anomalies,
                "lsb_analysis":   lsb_analysis,
                "file_size":      len(eng.data),
            })
        except Exception:
            self.error.emit(_tb.format_exc())


# ═══════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def lbl(text, obj_name=None, bold=False):
    l = QLabel(text)
    if obj_name: l.setObjectName(obj_name)
    if bold:
        f = l.font(); f.setBold(True); l.setFont(f)
    return l

def mono(text="", read_only=True):
    t = QTextEdit(text)
    t.setReadOnly(read_only)
    t.setFont(QFont("Consolas", 11))
    return t

def sep():
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet(f"color: {BORDER};")
    return f


# ═══════════════════════════════════════════════════════════════════════════
# TAB: OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════
class OverviewTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        self.file_label = lbl("No file loaded", "dim")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)
        layout.addWidget(sep())

        hg = QGroupBox("INTEGRITY HASHES")
        hl = QVBoxLayout(hg)
        self.hash_table = QTableWidget(0, 2)
        self.hash_table.setHorizontalHeaderLabels(["Algorithm", "Value"])
        self.hash_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.hash_table.setAlternatingRowColors(True)
        hl.addWidget(self.hash_table)
        layout.addWidget(hg)

        sg = QGroupBox("FILE SUMMARY")
        sl = QVBoxLayout(sg)
        self.summary = mono()
        self.summary.setMaximumHeight(220)
        sl.addWidget(self.summary)
        layout.addWidget(sg)
        layout.addStretch()

    def populate(self, results):
        self.file_label.setText(f"FILE:  {results['filepath']}")
        hashes = results["hashes"]
        self.hash_table.setRowCount(len(hashes))
        for i, (k, v) in enumerate(hashes.items()):
            self.hash_table.setItem(i, 0, QTableWidgetItem(k))
            vi = QTableWidgetItem(v)
            vi.setFont(QFont("Consolas", 11))
            self.hash_table.setItem(i, 1, vi)

        hits  = results["magic_hits"]
        anom  = results["anomalies"]
        fsize = results["file_size"]
        high_hits = [h for h in hits if h["confidence"] == "HIGH"]
        lines = [
            f"File size        : {fsize:,} bytes  ({fsize/1024/1024:.2f} MB)",
            f"Strings found    : {len(results['strings']):,}",
            f"Magic hits       : {len(hits)}  (HIGH confidence: {len(high_hits)})",
            f"Entropy edges    : {len(results['entropy_edges'])}",
            f"Anomalies found  : {len(anom)}",
            "",
            "RISK ASSESSMENT:",
        ]
        high = [a for a in anom if a["severity"] == "HIGH"]
        med  = [a for a in anom if a["severity"] == "MEDIUM"]
        if high:
            lines.append(f"  [HIGH]   {len(high)} issue(s)")
            for a in high:
                lines.append(f"     -> {a['type']}: {a['detail'][:80]}")
        if med:
            lines.append(f"  [MEDIUM] {len(med)} issue(s)")
            for a in med:
                lines.append(f"     -> {a['type']}")
        if not high and not med:
            lines.append("  [OK] No significant anomalies detected.")
        self.summary.setText("\n".join(lines))


# ═══════════════════════════════════════════════════════════════════════════
# TAB: METADATA
# ═══════════════════════════════════════════════════════════════════════════
class MetadataTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Value"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree)

    def populate(self, results):
        self.tree.clear()
        for section, fields in results["metadata"].items():
            parent = QTreeWidgetItem([section, ""])
            parent.setForeground(0, QColor(ACCENT))
            f = parent.font(0); f.setBold(True); parent.setFont(0, f)
            self.tree.addTopLevelItem(parent)
            if isinstance(fields, dict):
                for k, v in fields.items():
                    parent.addChild(QTreeWidgetItem([str(k), str(v)]))
            parent.setExpanded(True)


# ═══════════════════════════════════════════════════════════════════════════
# TAB: STRINGS  (BUG FIX: spinbox now triggers re-filter)
# ═══════════════════════════════════════════════════════════════════════════
class StringsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        bar = QHBoxLayout()
        bar.addWidget(lbl("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Type to filter strings...")
        self.filter_edit.textChanged.connect(self.apply_filter)
        bar.addWidget(self.filter_edit)

        bar.addWidget(lbl("Min length:"))
        self.minlen = QSpinBox()
        self.minlen.setRange(1, 200)
        self.minlen.setValue(4)
        # FIX: use valueChanged so spinbox immediately triggers re-filter
        self.minlen.valueChanged.connect(self.apply_filter)
        bar.addWidget(self.minlen)

        self.count_lbl = lbl("0 strings", "dim")
        bar.addWidget(self.count_lbl)
        layout.addLayout(bar)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Offset (hex)", "String"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setFont(QFont("Consolas", 11))
        layout.addWidget(self.table)
        self._all_strings = []

    def populate(self, results):
        self._all_strings = results["strings"]
        self.apply_filter()

    def apply_filter(self):
        filt = self.filter_edit.text().lower()
        minl = self.minlen.value()
        rows = [(off, s) for off, s in self._all_strings
                if len(s) >= minl and (not filt or filt in s.lower())]
        self.table.setRowCount(len(rows))
        for i, (off, s) in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(f"0x{off:X}" if off >= 0 else "UTF-16"))
            self.table.setItem(i, 1, QTableWidgetItem(s))
        self.count_lbl.setText(f"{len(rows):,} strings")


# ═══════════════════════════════════════════════════════════════════════════
# TAB: ANOMALIES
# ═══════════════════════════════════════════════════════════════════════════
class AnomalyTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("ANOMALY & STEGANOGRAPHY DETECTION", bold=True))
        layout.addWidget(lbl("Checks: LSB stego, data-after-EOF, entropy spikes, appended archives", "dim"))
        layout.addWidget(sep())

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Type", "Offset", "Detail"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        layout.addWidget(sep())
        self.detail = mono()
        self.detail.setMaximumHeight(130)
        layout.addWidget(lbl("SELECTED DETAIL", "dim"))
        layout.addWidget(self.detail)
        self.table.itemSelectionChanged.connect(self._on_select)

    def populate(self, results):
        anomalies = results["anomalies"]
        colors = {"HIGH": RED, "MEDIUM": AMBER, "LOW": GREEN}
        self.table.setRowCount(max(len(anomalies), 1))
        if not anomalies:
            ok = QTableWidgetItem("No anomalies detected")
            ok.setForeground(QColor(GREEN))
            self.table.setItem(0, 0, ok)
            return
        for i, a in enumerate(anomalies):
            sev = QTableWidgetItem(a["severity"])
            sev.setForeground(QColor(colors.get(a["severity"], TEXT)))
            f = sev.font(); f.setBold(True); sev.setFont(f)
            self.table.setItem(i, 0, sev)
            self.table.setItem(i, 1, QTableWidgetItem(a["type"]))
            self.table.setItem(i, 2, QTableWidgetItem(a["offset"]))
            self.table.setItem(i, 3, QTableWidgetItem(a["detail"]))

    def _on_select(self):
        row = self.table.currentRow()
        if row >= 0:
            parts = [self.table.item(row, c).text()
                     for c in range(self.table.columnCount())
                     if self.table.item(row, c)]
            self.detail.setText("\n".join(parts))


# ═══════════════════════════════════════════════════════════════════════════
# TAB: SCANNER (with confidence, hex preview, summary bar, dedup)
# ═══════════════════════════════════════════════════════════════════════════
class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("EMBEDDED FILE SCANNER", bold=True))
        layout.addWidget(lbl(f"Scanning {len(MAGIC_SIGNATURES)} magic signatures across all file types", "dim"))
        layout.addWidget(sep())

        # Summary bar
        self.summary_bar = QLabel("Run analysis to see results.")
        self.summary_bar.setStyleSheet(f"color:{AMBER}; font-size:11px; padding:4px 0;")
        layout.addWidget(self.summary_bar)

        # Filter bar
        bar = QHBoxLayout()
        bar.addWidget(lbl("Category:"))
        self.cat_filter = QComboBox()
        self.cat_filter.addItem("All")
        seen = set()
        for entry in MAGIC_SIGNATURES:
            cat = entry[4]
            if cat not in seen:
                self.cat_filter.addItem(cat)
                seen.add(cat)
        self.cat_filter.currentTextChanged.connect(self._filter)
        bar.addWidget(self.cat_filter)

        bar.addWidget(lbl("Confidence:"))
        self.conf_filter = QComboBox()
        self.conf_filter.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        self.conf_filter.currentTextChanged.connect(self._filter)
        bar.addWidget(self.conf_filter)

        self.plausible_only = QCheckBox("Plausible size only")
        self.plausible_only.setChecked(True)
        self.plausible_only.stateChanged.connect(self._filter)
        bar.addWidget(self.plausible_only)

        self.hit_count = lbl("0 hits", "dim")
        bar.addWidget(self.hit_count)
        bar.addStretch()
        layout.addLayout(bar)

        # Table — added Confidence and Hex Preview columns
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Decimal", "Hex Offset", "Confidence", "Category", "Type", "Est. Size", "Hex Preview"])
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setFont(QFont("Consolas", 10))
        layout.addWidget(self.table)

        self._all_hits = []

    def populate(self, results):
        self._all_hits = results["magic_hits"]
        # Build summary bar
        from collections import Counter
        cats = Counter(h["category"] for h in self._all_hits)
        summary = "  |  ".join(f"{cat}: {count}" for cat, count in sorted(cats.items()))
        self.summary_bar.setText(f"FOUND:  {summary}" if summary else "No signatures found.")
        self._filter()

    def _filter(self):
        cat  = self.cat_filter.currentText()
        conf = self.conf_filter.currentText()
        plaus = self.plausible_only.isChecked()

        hits = self._all_hits
        if cat  != "All":  hits = [h for h in hits if h["category"] == cat]
        if conf != "All":  hits = [h for h in hits if h["confidence"] == conf]
        if plaus:          hits = [h for h in hits if h.get("plausible", True)]

        conf_colors = {"HIGH": GREEN, "MEDIUM": AMBER, "LOW": RED}
        cat_colors  = {
            "Image": "#00CC88",    "Archive": AMBER,     "Executable": RED,
            "Video": "#AA88FF",    "Audio": "#FF88AA",   "Document": "#88CCFF",
            "Filesystem": "#FF8833", "Crypto": RED,       "Database": "#FFCC44",
            "Network": ACCENT,     "Font": "#CCFF88",    "Flash": "#FF6644",
            "Disk": AMBER,         "Firmware": RED,       "Text": TEXT,
            "Java": "#FF8800",     "Android": "#AAFFAA", "Email": "#FFAAFF",
            "Other": DIM,
        }

        self.table.setRowCount(len(hits))
        for i, h in enumerate(hits):
            self.table.setItem(i, 0, QTableWidgetItem(str(h["offset"])))
            self.table.setItem(i, 1, QTableWidgetItem(h["hex_offset"]))

            conf_item = QTableWidgetItem(h["confidence"])
            conf_item.setForeground(QColor(conf_colors.get(h["confidence"], TEXT)))
            f = conf_item.font(); f.setBold(True); conf_item.setFont(f)
            self.table.setItem(i, 2, conf_item)

            cat_item = QTableWidgetItem(h["category"])
            cat_item.setForeground(QColor(cat_colors.get(h["category"], TEXT)))
            self.table.setItem(i, 3, cat_item)

            name = h["name"]
            if h.get("dup_count", 0) > 0:
                name += f"  (x{h['dup_count']+1})"
            self.table.setItem(i, 4, QTableWidgetItem(name))

            sz = h["size_estimate"]
            self.table.setItem(i, 5, QTableWidgetItem(
                f"{sz:,} bytes" if isinstance(sz, int) else str(sz)))

            self.table.setItem(i, 6, QTableWidgetItem(h.get("hex_preview", "")))

        self.hit_count.setText(f"{len(hits)} hits shown")


# ═══════════════════════════════════════════════════════════════════════════
# TAB: ENTROPY
# ═══════════════════════════════════════════════════════════════════════════
class EntropyTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self._results = None

        if not HAS_MPL:
            layout.addWidget(lbl("matplotlib not available.", "dim"))
            return

        # ── Toolbar ───────────────────────────────────────────────────
        bar = QHBoxLayout()
        self.show_edges = QCheckBox("Show edges")
        self.show_edges.setChecked(True)
        self.show_edges.stateChanged.connect(self.redraw)
        self.show_hits = QCheckBox("Overlay magic hits")
        self.show_hits.setChecked(True)
        self.show_hits.stateChanged.connect(self.redraw)
        self.show_annotations = QCheckBox("Annotate spikes")
        self.show_annotations.setChecked(True)
        self.show_annotations.stateChanged.connect(self.redraw)
        self.show_bands = QCheckBox("Colored bands")
        self.show_bands.setChecked(True)
        self.show_bands.stateChanged.connect(self.redraw)
        bar.addWidget(self.show_edges)
        bar.addWidget(self.show_hits)
        bar.addWidget(self.show_annotations)
        bar.addWidget(self.show_bands)
        bar.addStretch()
        layout.addLayout(bar)

        # ── Graph + side legend splitter ──────────────────────────────
        hsplit = QSplitter(Qt.Orientation.Horizontal)

        graph_widget = QWidget()
        gl = QVBoxLayout(graph_widget)
        gl.setContentsMargins(0,0,0,0)
        self.fig = Figure(facecolor=MID)
        self.canvas = FigureCanvas(self.fig)
        gl.addWidget(self.canvas)
        hsplit.addWidget(graph_widget)

        # Side legend panel
        legend_widget = QWidget()
        legend_widget.setFixedWidth(220)
        legend_widget.setStyleSheet(f"background:{PANEL}; border-left:1px solid {BORDER};")
        ll = QVBoxLayout(legend_widget)
        ll.setContentsMargins(10,10,10,10)
        ll.setSpacing(4)
        ll.addWidget(lbl("IDENTIFIED REGIONS", bold=True))
        ll.addWidget(lbl("Files correlated to entropy spikes/dips", "dim"))
        ll.addWidget(sep())
        self.legend_list = QTextEdit()
        self.legend_list.setReadOnly(True)
        self.legend_list.setFont(QFont("Consolas", 10))
        self.legend_list.setStyleSheet(f"background:{PANEL}; border:none; color:{TEXT};")
        ll.addWidget(self.legend_list)
        hsplit.addWidget(legend_widget)
        hsplit.setSizes([800, 220])
        layout.addWidget(hsplit, stretch=1)

        # ── Edge table ────────────────────────────────────────────────
        self.edge_table = QTableWidget(0, 4)
        self.edge_table.setHorizontalHeaderLabels(
            ["Offset (hex)", "Direction", "Entropy", "Nearest File"])
        self.edge_table.setMaximumHeight(150)
        self.edge_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.edge_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(lbl("ENTROPY EDGES  —  correlated to detected file signatures", "dim"))
        layout.addWidget(self.edge_table)

    def _correlate(self, offset, hits, window=65536):
        """Find the closest HIGH-confidence magic hit within window bytes of offset."""
        best, best_dist = None, window
        for h in hits:
            if h.get("confidence") in ("HIGH", "MEDIUM"):
                dist = abs(h["offset"] - offset)
                if dist < best_dist:
                    best, best_dist = h, dist
        return best, best_dist

    def populate(self, results):
        self._results = results
        self.redraw()

    def redraw(self):
        if not self._results or not HAS_MPL:
            return
        results  = self._results
        blocks   = results["entropy_blocks"]
        edges    = results["entropy_edges"]
        hits     = results["magic_hits"]
        fsize    = results["file_size"]
        if not blocks:
            return

        CAT_COLORS = {
            "Image":      "#00CC88",
            "Archive":    "#FFB300",
            "Executable": "#FF4444",
            "Video":      "#AA88FF",
            "Audio":      "#FF88AA",
            "Email":      "#FFAAFF",
            "Document":   "#88CCFF",
            "Database":   "#FFCC44",
            "Network":    "#00E5FF",
            "Crypto":     "#FF6644",
            "Firmware":   "#FF8833",
            "Filesystem": "#FF9933",
            "Disk":       "#FFAA33",
            "Font":       "#CCFF88",
            "Flash":      "#FF7744",
            "Text":       "#AAAAAA",
            "Other":      "#666688",
        }

        self.fig.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(DARK)
        self.fig.patch.set_facecolor(MID)

        offsets   = [b[0] for b in blocks]
        entropies = [b[1] for b in blocks]

        # ── Base entropy line ─────────────────────────────────────────
        ax.plot(offsets, entropies, color=ACCENT, linewidth=1.2,
                alpha=0.9, label="Entropy", zorder=5)
        ax.fill_between(offsets, entropies, alpha=0.10, color=ACCENT)

        # ── Colored bands: for each HIGH hit, shade a region ──────────
        legend_entries = []
        annotated_offsets = set()

        if self.show_bands.isChecked():
            high_hits = [h for h in hits if h.get("confidence") in ("HIGH", "MEDIUM")]
            # Sort and pair up hits to define regions
            for i, h in enumerate(high_hits[:30]):
                color = CAT_COLORS.get(h["category"], "#888888")
                # Region: from this hit to next hit or +512KB
                next_off = high_hits[i+1]["offset"] if i+1 < len(high_hits) else h["offset"] + 524288
                region_end = min(next_off, fsize)
                # Only shade if region has notable entropy variation
                region_entropies = [e for o, e in zip(offsets, entropies)
                                    if h["offset"] <= o < region_end]
                if region_entropies and max(region_entropies) > 0.5:
                    ax.axvspan(h["offset"], region_end,
                               alpha=0.06, color=color, zorder=1)

        # ── High entropy highlight ────────────────────────────────────
        ax.fill_between(offsets, entropies,
                        where=[e > 0.95 for e in entropies],
                        color=RED, alpha=0.18, label="High entropy (>0.95)", zorder=2)

        # ── Edge markers ──────────────────────────────────────────────
        if self.show_edges.isChecked():
            for off, direction, ent in edges:
                ax.axvline(x=off,
                           color=GREEN if direction == "Rising" else AMBER,
                           alpha=0.5, linewidth=1, linestyle="--", zorder=3)

        # ── Magic hit verticals ───────────────────────────────────────
        if self.show_hits.isChecked():
            seen_cats = set()
            for h in [x for x in hits if x.get("confidence") in ("HIGH",)][:50]:
                color = CAT_COLORS.get(h["category"], "#888888")
                cat_label = h["category"] if h["category"] not in seen_cats else None
                ax.axvline(x=h["offset"], color=color, alpha=0.45,
                           linewidth=1.5, linestyle=":", label=cat_label, zorder=4)
                seen_cats.add(h["category"])

        # ── Spike/dip annotations ─────────────────────────────────────
        if self.show_annotations.isChecked():
            # Find local maxima and minima in entropy blocks
            annotation_candidates = []
            for i in range(1, len(blocks)-1):
                prev_e, curr_e, next_e = blocks[i-1][1], blocks[i][1], blocks[i+1][1]
                is_spike = curr_e > prev_e + 0.12 and curr_e > next_e + 0.08 and curr_e > 0.7
                is_dip   = curr_e < prev_e - 0.12 and curr_e < next_e - 0.08 and curr_e < 0.6
                if is_spike or is_dip:
                    annotation_candidates.append((blocks[i][0], blocks[i][1], "spike" if is_spike else "dip"))

            # Suppress annotations too close together
            filtered = []
            last_ann = -999999
            for off, ent, kind in annotation_candidates:
                if off - last_ann > fsize * 0.04:
                    filtered.append((off, ent, kind))
                    last_ann = off

            for off, ent, kind in filtered[:20]:
                nearest_hit, dist = self._correlate(off, hits)
                if nearest_hit:
                    label_text = f"{nearest_hit['name']}\n@0x{off:X}"
                    color = CAT_COLORS.get(nearest_hit["category"], "#AAAAAA")
                    y_pos = min(ent + 0.06, 1.0) if kind == "spike" else max(ent - 0.08, 0.02)
                    ax.annotate(
                        label_text,
                        xy=(off, ent),
                        xytext=(off, y_pos),
                        fontsize=7,
                        color=color,
                        ha="center",
                        arrowprops=dict(arrowstyle="-", color=color, alpha=0.6, lw=0.8),
                        bbox=dict(boxstyle="round,pad=0.2", facecolor=PANEL,
                                  edgecolor=color, alpha=0.85, linewidth=0.8),
                        zorder=10,
                    )
                    legend_entries.append((off, nearest_hit, ent, kind, dist))
                    annotated_offsets.add(off)

        # ── Axis styling ──────────────────────────────────────────────
        ticks = [int(fsize * i / 8) for i in range(9)]
        ax.set_xticks(ticks)
        ax.set_xticklabels([f"0x{t:X}" for t in ticks], rotation=30, ha="right", fontsize=8)
        ax.set_ylim(0, 1.15)
        ax.set_xlabel("File Offset", color=DIM, fontsize=10)
        ax.set_ylabel("Entropy  (0=structured  1=random)", color=DIM, fontsize=10)
        ax.set_title("ENTROPY ANALYSIS", color=ACCENT, fontsize=12, fontweight="bold")
        ax.tick_params(colors=DIM)
        for spine in ax.spines.values():
            spine.set_color(BORDER)
        ax.grid(True, color=BORDER, alpha=0.35, linewidth=0.5)

        # Compact legend (top right, only unique labels)
        handles, labels = ax.get_legend_handles_labels()
        seen, uniq_h, uniq_l = set(), [], []
        for h, l in zip(handles, labels):
            if l and l not in seen:
                uniq_h.append(h); uniq_l.append(l); seen.add(l)
        ax.legend(uniq_h, uniq_l, loc="upper right", facecolor=PANEL,
                  edgecolor=BORDER, labelcolor=TEXT, fontsize=8, ncol=2)

        self.canvas.draw()

        # ── Side legend panel ─────────────────────────────────────────
        if legend_entries:
            lines = []
            for off, h, ent, kind, dist in sorted(legend_entries, key=lambda x: x[0]):
                arrow = "^" if kind == "spike" else "v"
                lines.append(
                    f"{arrow} 0x{off:X}\n"
                    f"  {h['name']} ({h['category']})\n"
                    f"  entropy={ent:.3f}  dist={dist//1024}KB\n"
                )
            self.legend_list.setText("\n".join(lines))
        else:
            self.legend_list.setText("No correlated files found.\n\nRun analysis on a file\nwith embedded content.")

        # ── Edge table ────────────────────────────────────────────────
        self.edge_table.setRowCount(len(edges))
        for i, (off, direction, ent) in enumerate(edges):
            self.edge_table.setItem(i, 0, QTableWidgetItem(f"0x{off:X}"))
            di = QTableWidgetItem(direction)
            di.setForeground(QColor(GREEN if direction == "Rising" else AMBER))
            self.edge_table.setItem(i, 1, di)
            self.edge_table.setItem(i, 2, QTableWidgetItem(f"{ent:.6f}"))
            # Correlate edge to nearest file
            nearest, dist = self._correlate(off, hits, window=131072)
            if nearest:
                color = CAT_COLORS.get(nearest["category"], TEXT)
                corr_item = QTableWidgetItem(
                    f"{nearest['name']}  [{nearest['category']}]  dist={dist//1024}KB")
                corr_item.setForeground(QColor(color))
                self.edge_table.setItem(i, 3, corr_item)
            else:
                self.edge_table.setItem(i, 3, QTableWidgetItem("—"))


# ═══════════════════════════════════════════════════════════════════════════
# TAB: EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════
class ExtractorTab(QWidget):
    def __init__(self):
        super().__init__()
        self._results  = None
        self._filepath = None
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("BINARY SECTION EXTRACTOR", bold=True))
        layout.addWidget(lbl("Select a region and extract it. Add custom magic signatures below.", "dim"))
        layout.addWidget(sep())

        splitter = QSplitter(Qt.Orientation.Vertical)

        top = QWidget()
        tl  = QVBoxLayout(top)
        tl.addWidget(lbl("DETECTED REGIONS", "dim"))
        self.hit_table = QTableWidget(0, 5)
        self.hit_table.setHorizontalHeaderLabels(["Offset", "Hex", "Type", "Category", "Est. Size"])
        self.hit_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.hit_table.setAlternatingRowColors(True)
        self.hit_table.setFont(QFont("Consolas", 11))
        tl.addWidget(self.hit_table)

        eb = QHBoxLayout()
        self.extract_btn = QPushButton("EXTRACT SELECTED")
        self.extract_btn.setObjectName("success")
        self.extract_btn.clicked.connect(self.extract_selected)
        self.extract_all_btn = QPushButton("EXTRACT ALL HIGH CONFIDENCE")
        self.extract_all_btn.clicked.connect(self.extract_all)
        eb.addWidget(self.extract_btn)
        eb.addWidget(self.extract_all_btn)
        eb.addStretch()
        tl.addLayout(eb)
        splitter.addWidget(top)

        bot = QWidget()
        bl  = QVBoxLayout(bot)
        bl.addWidget(lbl("CUSTOM MAGIC SIGNATURES", "dim"))
        bl.addWidget(lbl("Format: NAME | HEXBYTES | OFFSET | .ext | Category | MinSizeBytes", "dim"))
        self.custom_edit = QTextEdit()
        self.custom_edit.setFont(QFont("Consolas", 11))
        self.custom_edit.setPlaceholderText("MyFormat | DEADBEEF | 0 | .bin | Unknown | 0")
        self.custom_edit.setMaximumHeight(100)
        bl.addWidget(self.custom_edit)

        rb = QHBoxLayout()
        self.rescan_btn = QPushButton("RESCAN WITH CUSTOM SIGS")
        self.rescan_btn.clicked.connect(self.rescan)
        rb.addWidget(self.rescan_btn)
        rb.addStretch()
        bl.addLayout(rb)

        self.log = mono()
        self.log.setMaximumHeight(100)
        bl.addWidget(lbl("EXTRACTION LOG", "dim"))
        bl.addWidget(self.log)
        splitter.addWidget(bot)
        layout.addWidget(splitter)

    def populate(self, results):
        self._results  = results
        self._filepath = results["filepath"]
        self._fill_table(results["magic_hits"])

    def _fill_table(self, hits):
        self.hit_table.setRowCount(len(hits))
        for i, h in enumerate(hits):
            self.hit_table.setItem(i, 0, QTableWidgetItem(str(h["offset"])))
            self.hit_table.setItem(i, 1, QTableWidgetItem(h["hex_offset"]))
            self.hit_table.setItem(i, 2, QTableWidgetItem(h["name"]))
            self.hit_table.setItem(i, 3, QTableWidgetItem(h["category"]))
            sz = h["size_estimate"]
            self.hit_table.setItem(i, 4, QTableWidgetItem(
                f"{sz:,} bytes" if isinstance(sz, int) else str(sz)))

    def extract_selected(self):
        row = self.hit_table.currentRow()
        if row < 0:
            self.log.append("No row selected.")
            return
        if self._results and row < len(self._results["magic_hits"]):
            self._do_extract(self._results["magic_hits"][row])

    def extract_all(self):
        if self._results:
            high = [h for h in self._results["magic_hits"] if h["confidence"] == "HIGH"]
            for h in high:
                self._do_extract(h)
            self.log.append(f"Extracted {len(high)} HIGH confidence hits.")

    def _do_extract(self, hit):
        try:
            with open(self._filepath, "rb") as f:
                f.seek(hit["offset"])
                sz   = hit["size_estimate"]
                data = f.read(sz if isinstance(sz, int) and 0 < sz < 500_000_000 else 65536)
            out_dir  = Path(self._filepath).parent / "forensix_extracted"
            out_dir.mkdir(exist_ok=True)
            out_path = out_dir / f"offset_{hit['offset']:08X}{hit['extension']}"
            with open(out_path, "wb") as f:
                f.write(data)
            self.log.append(f"OK  [{hit['confidence']}] {len(data):,} bytes -> {out_path.name}")
        except Exception as e:
            self.log.append(f"FAIL  {e}")

    def rescan(self):
        if not self._results:
            return
        custom = []
        for line in self.custom_edit.toPlainText().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 5:
                try:
                    name, hexbytes, offset, ext, cat = parts[:5]
                    min_sz = int(parts[5]) if len(parts) > 5 else 0
                    custom.append((name, hexbytes, int(offset), ext, cat, min_sz, 0))
                except Exception:
                    self.log.append(f"Could not parse: {line}")
        if custom:
            eng = AnalysisEngine(self._filepath)
            eng.load()
            hits = eng.scan_magic(extra_sigs=custom)
            self._results["magic_hits"] = hits
            self._fill_table(hits)
            self.log.append(f"Rescanned with {len(custom)} custom sig(s). {len(hits)} hits.")
        else:
            self.log.append("No valid custom signatures found.")


# ═══════════════════════════════════════════════════════════════════════════
# TAB: STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════════════════
class StegTab(QWidget):
    def __init__(self):
        super().__init__()
        self._lsb = None
        layout = QVBoxLayout(self)

        layout.addWidget(lbl("LSB STEGANOGRAPHY ANALYSIS", bold=True))
        layout.addWidget(lbl("Supports PNG, BMP, TIFF, JPEG. Runs chi-square test, LSB ratio analysis, and auto-extraction.", "dim"))
        layout.addWidget(sep())

        # Verdict banner
        self.verdict_lbl = QLabel("No analysis run yet.")
        self.verdict_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verdict_lbl.setFixedHeight(44)
        self.verdict_lbl.setStyleSheet(
            f"background:{PANEL}; color:{DIM}; font-size:15px; font-weight:bold; letter-spacing:3px; border:1px solid {BORDER};")
        layout.addWidget(self.verdict_lbl)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: stats panel ──────────────────────────────────────────
        left = QWidget()
        ll = QVBoxLayout(left)

        ll.addWidget(lbl("STATISTICAL TESTS", "dim"))
        self.stats_table = QTableWidget(0, 2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.stats_table.setAlternatingRowColors(True)
        self.stats_table.setMaximumHeight(280)
        ll.addWidget(self.stats_table)

        ll.addWidget(sep())
        ll.addWidget(lbl("EXTRACTED CONTENT", "dim"))
        self.extracted = mono()
        ll.addWidget(self.extracted)

        save_bar = QHBoxLayout()
        self.save_btn = QPushButton("SAVE EXTRACTED BYTES")
        self.save_btn.setObjectName("success")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save_extracted)
        save_bar.addWidget(self.save_btn)
        save_bar.addStretch()
        ll.addLayout(save_bar)
        splitter.addWidget(left)

        # ── Right: noise map ───────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(lbl("LSB NOISE MAP", "dim"))
        rl.addWidget(lbl("Each pixel shows only the LSB of each channel amplified to 0 or 255.", "dim"))
        rl.addWidget(lbl("Hidden data = structured pattern. Clean image = random scatter.", "dim"))

        self.noise_label = QLabel()
        self.noise_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.noise_label.setMinimumSize(300, 300)
        self.noise_label.setStyleSheet(f"background:{MID}; border:1px solid {BORDER};")
        self.noise_label.setText("Noise map will appear here after analysis of an image file.")
        rl.addWidget(self.noise_label, stretch=1)

        save_noise_bar = QHBoxLayout()
        self.save_noise_btn = QPushButton("SAVE NOISE MAP")
        self.save_noise_btn.setEnabled(False)
        self.save_noise_btn.clicked.connect(self._save_noise)
        save_noise_bar.addWidget(self.save_noise_btn)
        save_noise_bar.addStretch()
        rl.addLayout(save_noise_bar)
        splitter.addWidget(right)

        splitter.setSizes([500, 500])
        layout.addWidget(splitter)

    def populate(self, results):
        lsb = results.get("lsb_analysis")
        self._lsb = lsb

        if not lsb:
            self.verdict_lbl.setText("NOT AN IMAGE FILE")
            self.verdict_lbl.setStyleSheet(
                f"background:{PANEL}; color:{DIM}; font-size:15px; font-weight:bold; letter-spacing:3px; border:1px solid {BORDER};")
            self.stats_table.setRowCount(0)
            self.extracted.setText("LSB analysis only applies to image files (PNG, BMP, TIFF, JPEG).")
            return

        verdict = lsb.get("verdict", "UNKNOWN")
        verdict_colors = {
            "DETECTED":  (RED,   f"background:#2A0A0A; color:{RED};"),
            "SUSPECTED": (AMBER, f"background:#2A1A00; color:{AMBER};"),
            "CLEAN":     (GREEN, f"background:#0A1A0A; color:{GREEN};"),
            "NOT_IMAGE": (DIM,   f"background:{PANEL}; color:{DIM};"),
            "ERROR":     (DIM,   f"background:{PANEL}; color:{DIM};"),
        }
        _, style = verdict_colors.get(verdict, (DIM, f"background:{PANEL}; color:{DIM};"))
        self.verdict_lbl.setText(f"LSB VERDICT:  {verdict}")
        self.verdict_lbl.setStyleSheet(
            style + " font-size:15px; font-weight:bold; letter-spacing:3px; border:1px solid;")

        # Stats table
        ch_names = ["Red", "Green", "Blue"]
        ratios   = lsb.get("lsb_ratios", [0,0,0])
        chis     = lsb.get("chi_scores",  [0,0,0])
        rows = []
        rows.append(("Image size",        f"{lsb.get('image_size', ('?','?'))[0]} x {lsb.get('image_size',('?','?'))[1]} px"))
        rows.append(("Total pixels",      f"{lsb.get('total_pixels', 0):,}"))
        rows.append(("LSB capacity",      f"{lsb.get('capacity_bytes', 0):,} bytes  ({lsb.get('capacity_bytes',0)/1024:.1f} KB)"))
        rows.append(("",                  ""))
        for i, ch in enumerate(ch_names):
            rows.append((f"LSB ratio — {ch}",     f"{ratios[i]:.6f}  {'⚠ suspicious' if 0.47 < ratios[i] < 0.53 else 'ok'}"))
        rows.append(("",                  ""))
        for i, ch in enumerate(ch_names):
            rows.append((f"Chi-square — {ch}",    f"{chis[i]:.2f}"))
        rows.append(("Chi variance",      f"{lsb.get('chi_variance',0):.2f}  {'⚠ uniform (suspicious)' if lsb.get('chi_variance',0) < 500 else 'ok'}"))
        rows.append(("Avg chi",           f"{lsb.get('avg_chi',0):.2f}"))

        self.stats_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            self.stats_table.setItem(i, 0, QTableWidgetItem(k))
            vi = QTableWidgetItem(v)
            if "suspicious" in v:
                vi.setForeground(QColor(AMBER))
            self.stats_table.setItem(i, 1, vi)

        # Extracted content
        lines = []
        if lsb.get("extracted_text"):
            lines.append(f"HIDDEN TEXT FOUND:")
            lines.append(f'  "{lsb["extracted_text"]}"')
            lines.append("")
            self.save_btn.setEnabled(True)
        elif lsb.get("extracted_magic"):
            lines.append(f"EMBEDDED FILE DETECTED:")
            lines.append(f"  Type: {lsb['extracted_magic']}")
            lines.append(f"  Use SAVE EXTRACTED BYTES to recover the file.")
            self.save_btn.setEnabled(True)
        else:
            lines.append("No readable hidden content auto-extracted.")
            lines.append("")
            lines.append("If you suspect stego, the LSB noise map may reveal patterns.")
            lines.append("A structured/repetitive noise map indicates hidden data.")
            self.save_btn.setEnabled(False)

        lines.append("")
        lines.append(f"Summary: {lsb.get('summary','')}")
        self.extracted.setText("\n".join(lines))

        # Noise map
        noise_path = lsb.get("noise_path")
        if noise_path and os.path.exists(noise_path):
            try:
                from PyQt6.QtGui import QPixmap
                px = QPixmap(noise_path)
                self.noise_label.setPixmap(
                    px.scaled(self.noise_label.width() or 400,
                              self.noise_label.height() or 400,
                              Qt.AspectRatioMode.KeepAspectRatio,
                              Qt.TransformationMode.SmoothTransformation))
                self.save_noise_btn.setEnabled(True)
            except Exception as e:
                self.noise_label.setText(f"Could not render noise map: {e}")
        else:
            self.noise_label.setText("Noise map not available.")

    def _save_extracted(self):
        if not self._lsb:
            return
        data = self._lsb.get("extracted_bytes")
        text = self._lsb.get("extracted_text")
        magic = self._lsb.get("extracted_magic", "")

        # Guess extension
        ext = ".bin"
        if text:
            ext = ".txt"
        elif "JPEG" in magic:   ext = ".jpg"
        elif "PNG"  in magic:   ext = ".png"
        elif "ZIP"  in magic:   ext = ".zip"
        elif "PDF"  in magic:   ext = ".pdf"
        elif "MP3"  in magic:   ext = ".mp3"
        elif "ELF"  in magic:   ext = ".elf"
        elif "Exec" in magic:   ext = ".exe"

        path, _ = QFileDialog.getSaveFileName(self, "Save Extracted Data", f"lsb_extracted{ext}", "All Files (*)")
        if not path:
            return
        if data:
            with open(path, "wb") as f:
                f.write(data)
        elif text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        QMessageBox.information(self, "Saved", f"Extracted data saved to:\n{path}")

    def _save_noise(self):
        if not self._lsb:
            return
        noise_path = self._lsb.get("noise_path")
        if not noise_path or not os.path.exists(noise_path):
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Noise Map", "lsb_noise_map.png", "PNG (*.png)")
        if path:
            import shutil
            shutil.copy(noise_path, path)
            QMessageBox.information(self, "Saved", f"Noise map saved to:\n{path}")


# ═══════════════════════════════════════════════════════════════════════════
# TAB: CONTACT
# ═══════════════════════════════════════════════════════════════════════════
class ContactTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Full-width banner ─────────────────────────────────────────
        banner = QWidget()
        banner.setFixedHeight(180)
        banner.setStyleSheet(f"background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {MID}, stop:0.5 #0A1520, stop:1 {MID}); border-bottom: 1px solid {BORDER};")
        bl = QVBoxLayout(banner)
        bl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        name_lbl = QLabel("DANIEL BEN YEHUDA")
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet(f"color:{ACCENT}; font-size:28px; font-weight:bold; letter-spacing:6px; background:transparent;")
        bl.addWidget(name_lbl)

        role_lbl = QLabel("Creator of FORENSIX  //  Digital Forensics Suite")
        role_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        role_lbl.setStyleSheet(f"color:{DIM}; font-size:13px; letter-spacing:2px; background:transparent;")
        bl.addWidget(role_lbl)

        layout.addWidget(banner)

        # ── Content area ──────────────────────────────────────────────
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(80, 50, 80, 50)
        cl.setSpacing(30)
        cl.setAlignment(Qt.AlignmentFlag.AlignTop)

        cl.addWidget(sep())

        # LinkedIn
        linkedin_group = QGroupBox("LINKEDIN")
        ll = QHBoxLayout(linkedin_group)
        ll.setContentsMargins(20, 16, 20, 16)

        li_icon = QLabel("in")
        li_icon.setFixedSize(40, 40)
        li_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        li_icon.setStyleSheet(f"background:#0077B5; color:white; font-size:18px; font-weight:bold; border-radius:6px;")
        ll.addWidget(li_icon)

        li_text = QVBoxLayout()
        li_label = QLabel("LinkedIn Profile")
        li_label.setStyleSheet(f"color:{DIM}; font-size:11px; letter-spacing:1px;")
        li_url = QLabel("www.linkedin.com/in/daniel-by")
        li_url.setStyleSheet(f"color:{ACCENT}; font-size:14px;")
        li_url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        li_text.addWidget(li_label)
        li_text.addWidget(li_url)
        ll.addLayout(li_text)
        ll.addStretch()

        copy_li_btn = QPushButton("COPY")
        copy_li_btn.setFixedWidth(80)
        copy_li_btn.clicked.connect(lambda: self._copy("https://www.linkedin.com/in/daniel-by", copy_li_btn))
        ll.addWidget(copy_li_btn)
        cl.addWidget(linkedin_group)

        # Email
        email_group = QGroupBox("EMAIL")
        el = QHBoxLayout(email_group)
        el.setContentsMargins(20, 16, 20, 16)

        em_icon = QLabel("@")
        em_icon.setFixedSize(40, 40)
        em_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        em_icon.setStyleSheet(f"background:{PANEL}; color:{ACCENT}; font-size:20px; font-weight:bold; border-radius:6px; border:1px solid {BORDER};")
        el.addWidget(em_icon)

        em_text = QVBoxLayout()
        em_label = QLabel("ProtonMail")
        em_label.setStyleSheet(f"color:{DIM}; font-size:11px; letter-spacing:1px;")
        em_addr = QLabel("benyehudad@protonmail.com")
        em_addr.setStyleSheet(f"color:{ACCENT}; font-size:14px;")
        em_addr.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        em_text.addWidget(em_label)
        em_text.addWidget(em_addr)
        el.addLayout(em_text)
        el.addStretch()

        copy_em_btn = QPushButton("COPY")
        copy_em_btn.setFixedWidth(80)
        copy_em_btn.clicked.connect(lambda: self._copy("benyehudad@protonmail.com", copy_em_btn))
        el.addWidget(copy_em_btn)
        cl.addWidget(email_group)

        cl.addWidget(sep())

        # About blurb
        about = QLabel(
            "FORENSIX is an open digital forensics analysis suite for detecting\n"
            "hidden files, steganography, entropy anomalies, and embedded payloads.\n"
            "Built with PyQt6, matplotlib, and Pillow."
        )
        about.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about.setStyleSheet(f"color:{DIM}; font-size:12px; line-height:1.8;")
        cl.addWidget(about)
        cl.addStretch()

        layout.addWidget(content)

    def _copy(self, text, btn):
        QApplication.clipboard().setText(text)
        original = btn.text()
        btn.setText("COPIED!")
        btn.setStyleSheet(f"background:{GREEN}; color:{DARK}; border-color:{GREEN};")
        QTimer.singleShot(1500, lambda: (btn.setText(original), btn.setStyleSheet("")))


# ═══════════════════════════════════════════════════════════════════════════
# BREAKING MACHINE ANIMATION OVERLAY
# ═══════════════════════════════════════════════════════════════════════════
class BreakingMachineOverlay(QWidget):
    """
    Full-window translucent overlay showing a machine being broken apart
    while analysis runs. Drawn entirely with QPainter — no external assets.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setGeometry(parent.rect())

        self._tick     = 0
        self._progress = 0
        self._msg      = "Initializing..."
        self._done     = False

        # Machine parts: each is (name, base_x, base_y, w, h, color, phase_offset)
        self._parts = [
            ("HOUSING",   0,    0,  120,  80, "#1C3050", 0.0),
            ("GEAR_L",  -55,  -10,   40,  40, "#00E5FF", 0.3),
            ("GEAR_R",   55,  -10,   40,  40, "#00FF9D", 0.5),
            ("PIPE_T",    0,  -50,   20,  30, "#FFB300", 0.1),
            ("PIPE_B",    0,   50,   20,  30, "#FFB300", 0.7),
            ("BOLT_TL", -48, -34,   12,  12, "#FF4444", 0.2),
            ("BOLT_TR",  48, -34,   12,  12, "#FF4444", 0.4),
            ("BOLT_BL", -48,  34,   12,  12, "#FF4444", 0.6),
            ("BOLT_BR",  48,  34,   12,  12, "#FF4444", 0.8),
            ("SCREEN",   -5,  -8,   50,  30, "#0A1A2A", 0.0),
            ("ANTENNA", -20, -70,    8,  25, "#00E5FF", 0.9),
            ("VENT_1",   20,  20,   30,   8, "#252A3A", 0.15),
            ("VENT_2",   20,  30,   30,   8, "#252A3A", 0.25),
            ("VENT_3",   20,  40,   30,   8, "#252A3A", 0.35),
        ]

        # Per-part explosion state: dx, dy, angle, spin, scale
        import random
        rng = random.Random(42)
        self._explosion = []
        for _ in self._parts:
            self._explosion.append({
                "dx":    rng.uniform(-3, 3),
                "vy":    rng.uniform(-4, 1),
                "spin":  rng.uniform(-8, 8),
                "angle": 0.0,
                "ox":    0.0,
                "oy":    0.0,
                "scale": 1.0,
            })

        # Sparks
        self._sparks = []
        for _ in range(40):
            self._sparks.append({
                "x":    rng.uniform(-80, 80),
                "y":    rng.uniform(-60, 60),
                "vx":   rng.uniform(-6, 6),
                "vy":   rng.uniform(-8, 2),
                "life": rng.uniform(0.2, 1.0),
                "max":  rng.uniform(0.5, 1.5),
                "color": rng.choice(["#00E5FF","#FFB300","#FF4444","#00FF9D","#FFFFFF"]),
            })

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_fn)
        self._timer.start(33)  # ~30fps

    def set_progress(self, val, msg):
        self._progress = val
        self._msg      = msg
        if val >= 100:
            self._done = True
            QTimer.singleShot(600, self._finish)

    def _finish(self):
        self._timer.stop()
        self.hide()
        self.deleteLater()

    def _tick_fn(self):
        self._tick += 1
        t = self._tick
        # Progress 0-100 maps to "shake" then "explode" then "done"
        p = self._progress / 100.0

        # Shake phase (0-60%): parts vibrate
        # Explode phase (60-100%): parts fly apart
        shake_strength = min(p * 2, 1.0) * 4
        explode_phase  = max(0, (p - 0.55) / 0.45)

        import math
        for i, state in enumerate(self._explosion):
            part = self._parts[i]
            phase = part[6]
            shake_x = math.sin(t * 0.4 + phase * 10) * shake_strength
            shake_y = math.cos(t * 0.3 + phase * 8)  * shake_strength * 0.5

            if explode_phase > 0:
                gravity = 0.15 * explode_phase
                state["vy"] += gravity
                state["ox"] += state["dx"] * explode_phase * 2.5
                state["oy"] += state["vy"] * explode_phase * 2.0
                state["angle"] += state["spin"] * explode_phase
                state["scale"] = max(0.1, 1.0 - explode_phase * 0.6)
            else:
                state["ox"] = shake_x
                state["oy"] = shake_y

        # Animate sparks
        for sp in self._sparks:
            sp["x"]   += sp["vx"] * 0.3 * (1 + explode_phase * 3)
            sp["y"]   += sp["vy"] * 0.3 * (1 + explode_phase * 3)
            sp["vy"]  += 0.08
            sp["life"] -= 0.008 + explode_phase * 0.015
            if sp["life"] <= 0:
                sp["life"] = sp["max"]
                sp["x"] = 0; sp["y"] = 0
                import random
                sp["vx"] = random.uniform(-6,6)
                sp["vy"] = random.uniform(-8,2)

        self.update()

    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QRadialGradient, QLinearGradient
        from PyQt6.QtCore import QRectF, QPointF
        import math

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        W, H = self.width(), self.height()
        cx, cy = W // 2, H // 2

        # ── Background dim ────────────────────────────────────────────
        painter.fillRect(0, 0, W, H, QColor(0, 0, 0, 180))

        # ── Scanlines effect ──────────────────────────────────────────
        pen = QPen(QColor(0, 229, 255, 8))
        pen.setWidth(1)
        painter.setPen(pen)
        for y in range(0, H, 4):
            painter.drawLine(0, y, W, y)

        # ── Status text ───────────────────────────────────────────────
        painter.setPen(QColor(ACCENT))
        f = QFont("Consolas", 11)
        painter.setFont(f)
        painter.drawText(QRectF(0, cy + 160, W, 30),
                         Qt.AlignmentFlag.AlignCenter, self._msg.upper())

        # ── Progress bar ──────────────────────────────────────────────
        bar_w, bar_h = 400, 6
        bar_x = cx - bar_w // 2
        bar_y = cy + 190
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(37, 42, 58))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 3, 3)
        fill_w = int(bar_w * self._progress / 100)
        if fill_w > 0:
            painter.setBrush(QColor(ACCENT))
            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 3, 3)

        pct_font = QFont("Consolas", 10)
        painter.setFont(pct_font)
        painter.setPen(QColor(DIM))
        painter.drawText(QRectF(0, bar_y + 12, W, 20),
                         Qt.AlignmentFlag.AlignCenter,
                         f"ANALYZING...  {self._progress}%")

        # ── Title ─────────────────────────────────────────────────────
        tf = QFont("Consolas", 14)
        tf.setBold(True)
        painter.setFont(tf)
        painter.setPen(QColor(ACCENT))
        painter.drawText(QRectF(0, cy - 230, W, 30),
                         Qt.AlignmentFlag.AlignCenter, "FORENSIX  //  ANALYZING")

        # ── Machine parts ─────────────────────────────────────────────
        t = self._tick
        explode_phase = max(0, (self._progress / 100.0 - 0.55) / 0.45)

        for i, (name, bx, by, pw, ph, color, phase) in enumerate(self._parts):
            state = self._explosion[i]
            px = cx + bx + state["ox"]
            py = cy + by + state["oy"]
            sc = state["scale"]
            angle = state["angle"]

            alpha = max(0, min(255, int(255 * (1 - explode_phase * 0.8))))
            if alpha <= 0:
                continue

            painter.save()
            painter.translate(px, py)
            painter.rotate(angle)
            painter.scale(sc, sc)

            c = QColor(color)
            c.setAlpha(alpha)

            if name == "SCREEN":
                # Draw screen with scanline flicker
                painter.setBrush(QColor(10, 26, 42, alpha))
                painter.setPen(QPen(QColor(0, 229, 255, alpha), 1))
                painter.drawRect(-pw//2, -ph//2, pw, ph)
                # Text on screen
                sf = QFont("Consolas", 5)
                painter.setFont(sf)
                painter.setPen(QColor(0, 229, 255, int(alpha * 0.8)))
                tick_char = "|" if (t // 8) % 2 == 0 else "_"
                painter.drawText(-pw//2 + 3, -ph//2 + 10, f"SCAN{tick_char}")
                painter.drawText(-pw//2 + 3, -ph//2 + 18, f"{self._progress:>3d}%")

            elif "GEAR" in name:
                # Draw gear as circle with teeth
                painter.setBrush(QBrush(c))
                painter.setPen(QPen(QColor(0,0,0,alpha), 1))
                r = pw // 2
                gear_angle = t * (3 if "L" in name else -3) * (1 + explode_phase)
                painter.rotate(gear_angle)
                painter.drawEllipse(-r, -r, r*2, r*2)
                # Teeth
                tooth_pen = QPen(c, 4)
                painter.setPen(tooth_pen)
                for tooth in range(8):
                    ta = math.radians(tooth * 45)
                    x1 = math.cos(ta) * r
                    y1 = math.sin(ta) * r
                    x2 = math.cos(ta) * (r + 7)
                    y2 = math.sin(ta) * (r + 7)
                    painter.drawLine(int(x1), int(y1), int(x2), int(y2))
                # Center hole
                painter.setBrush(QColor(DARK))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(-6, -6, 12, 12)

            elif "BOLT" in name:
                painter.setBrush(QBrush(c))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(-pw//2, -ph//2, pw, ph)
                painter.setPen(QPen(QColor(DARK), 2))
                painter.drawLine(-4, 0, 4, 0)
                painter.drawLine(0, -4, 0, 4)

            elif "PIPE" in name:
                painter.setBrush(QBrush(c))
                painter.setPen(QPen(QColor(DARK), 1))
                painter.drawRect(-pw//2, -ph//2, pw, ph)
                # Flow indicator
                if not self._done:
                    flow_pos = (t * 3 + i * 20) % ph - ph//2
                    painter.setPen(QPen(QColor(255,255,255,80), 1))
                    painter.drawLine(-pw//2+2, flow_pos, pw//2-2, flow_pos)

            elif "VENT" in name:
                painter.setBrush(QBrush(c))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRect(-pw//2, -ph//2, pw, ph)
                # Slats
                painter.setPen(QPen(QColor(DARK), 1))
                for sx in range(-pw//2 + 4, pw//2, 6):
                    painter.drawLine(sx, -ph//2 + 1, sx, ph//2 - 1)

            elif name == "ANTENNA":
                painter.setPen(QPen(c, 2))
                painter.drawLine(0, 0, 0, -ph)
                # Blink
                if (t // 12) % 2 == 0:
                    painter.setBrush(QColor(RED))
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.drawEllipse(-3, -ph-3, 6, 6)

            else:  # HOUSING
                painter.setBrush(QBrush(c))
                painter.setPen(QPen(QColor(0, 229, 255, alpha // 2), 2))
                painter.drawRoundedRect(-pw//2, -ph//2, pw, ph, 8, 8)
                # Label
                lf = QFont("Consolas", 6)
                lf.setBold(True)
                painter.setFont(lf)
                painter.setPen(QColor(0, 229, 255, alpha // 2))
                painter.drawText(-pw//2 + 4, ph//2 - 4, "FORENSIX v2")

            painter.restore()

        # ── Sparks ────────────────────────────────────────────────────
        for sp in self._sparks:
            if sp["life"] <= 0:
                continue
            alpha = int(255 * min(sp["life"] / sp["max"], 1.0))
            sc = QColor(sp["color"])
            sc.setAlpha(alpha)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(sc)
            sx = cx + sp["x"]
            sy = cy + sp["y"]
            r = max(1, int(2 * sp["life"] / sp["max"]))
            painter.drawEllipse(int(sx-r), int(sy-r), r*2, r*2)
            # Spark trail
            trail = QColor(sp["color"])
            trail.setAlpha(alpha // 3)
            painter.setPen(QPen(trail, 1))
            painter.drawLine(int(sx), int(sy),
                             int(sx - sp["vx"]*2), int(sy - sp["vy"]*2))

        # ── Done flash ────────────────────────────────────────────────
        if self._done:
            flash_alpha = max(0, int(200 * (1 - (self._tick % 20) / 20)))
            painter.fillRect(0, 0, W, H, QColor(0, 229, 255, flash_alpha // 6))
            painter.setPen(QColor(0, 229, 255, flash_alpha))
            df = QFont("Consolas", 18)
            df.setBold(True)
            painter.setFont(df)
            painter.drawText(QRectF(0, cy - 30, W, 60),
                             Qt.AlignmentFlag.AlignCenter, "ANALYSIS COMPLETE")

        painter.end()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════
class ForensixWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FORENSIX  //  Digital Forensic Suite  |  By Daniel Ben Yehuda")
        self.showFullScreen()
        self.setStyleSheet(QSS)
        self._results = None
        self._worker  = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet(f"background:{MID}; border-bottom:1px solid {BORDER};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)

        title = QLabel("FORENSIX")
        title.setStyleSheet(f"color:{ACCENT}; font-size:18px; font-weight:bold; letter-spacing:4px;")
        hl.addWidget(title)
        sub = QLabel("Digital Forensic Suite  |  By Daniel Ben Yehuda")
        sub.setStyleSheet(f"color:{DIM}; font-size:11px; letter-spacing:1px;")
        hl.addWidget(sub)
        hl.addStretch()

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("No file selected...")
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setMinimumWidth(350)
        hl.addWidget(self.file_path_edit)

        browse_btn = QPushButton("BROWSE")
        browse_btn.clicked.connect(self.browse_file)
        hl.addWidget(browse_btn)

        self.analyze_btn = QPushButton("ANALYZE")
        self.analyze_btn.setObjectName("primary")
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        hl.addWidget(self.analyze_btn)

        export_btn = QPushButton("EXPORT")
        export_btn.clicked.connect(self.export_report)
        hl.addWidget(export_btn)

        quit_btn = QPushButton("X")
        quit_btn.setObjectName("danger")
        quit_btn.setFixedWidth(40)
        quit_btn.clicked.connect(self.close)
        hl.addWidget(quit_btn)

        root.addWidget(header)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(3)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet(
            f"QProgressBar{{border:none;background:{MID};}}"
            f"QProgressBar::chunk{{background:{ACCENT};}}"
        )
        root.addWidget(self.progress)

        self.tabs = QTabWidget()
        self.tab_overview  = OverviewTab()
        self.tab_metadata  = MetadataTab()
        self.tab_strings   = StringsTab()
        self.tab_anomaly   = AnomalyTab()
        self.tab_scanner   = ScannerTab()
        self.tab_entropy   = EntropyTab()
        self.tab_steg      = StegTab()
        self.tab_extractor = ExtractorTab()
        self.tab_contact   = ContactTab()

        self.tabs.addTab(self.tab_overview,  "Overview")
        self.tabs.addTab(self.tab_metadata,  "Metadata")
        self.tabs.addTab(self.tab_strings,   "Strings")
        self.tabs.addTab(self.tab_anomaly,   "Anomalies")
        self.tabs.addTab(self.tab_scanner,   "Scanner")
        self.tabs.addTab(self.tab_entropy,   "Entropy")
        self.tabs.addTab(self.tab_steg,      "Steganography")
        self.tabs.addTab(self.tab_extractor, "Extractor")
        self.tabs.addTab(self.tab_contact,   "Contact")
        root.addWidget(self.tabs)

        self.status_lbl = QLabel("  Ready. Select a file to begin.")
        self.status_lbl.setFixedHeight(24)
        self.status_lbl.setStyleSheet(
            f"color:{DIM}; font-size:11px; padding-left:20px; background:{MID};")
        root.addWidget(self.status_lbl)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to analyze", "", "All Files (*)")
        if path:
            self.file_path_edit.setText(path)
            self.analyze_btn.setEnabled(True)
            self.status_lbl.setText(f"  Selected: {path}")

    def start_analysis(self):
        path = self.file_path_edit.text()
        if not path or not os.path.exists(path):
            return
        self.analyze_btn.setEnabled(False)
        self.progress.setValue(0)

        # Launch overlay animation
        self._overlay = BreakingMachineOverlay(self)
        self._overlay.show()
        self._overlay.raise_()

        self._worker = AnalysisWorker(path)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, val, msg):
        self.progress.setValue(val)
        self.status_lbl.setText(f"  {msg}")
        if hasattr(self, '_overlay') and self._overlay:
            self._overlay.set_progress(val, msg)

    def _on_done(self, results):
        self._results = results
        self.analyze_btn.setEnabled(True)
        self.progress.setValue(100)
        self.status_lbl.setText(
            f"  Done — {len(results['magic_hits'])} signatures, "
            f"{len(results['anomalies'])} anomalies, "
            f"{len(results['strings']):,} strings"
        )
        if hasattr(self, '_overlay') and self._overlay:
            self._overlay.set_progress(100, "Analysis complete")
        self.tab_overview.populate(results)
        self.tab_metadata.populate(results)
        self.tab_strings.populate(results)
        self.tab_anomaly.populate(results)
        self.tab_scanner.populate(results)
        self.tab_entropy.populate(results)
        self.tab_steg.populate(results)
        self.tab_extractor.populate(results)

    def _on_error(self, msg):
        self.analyze_btn.setEnabled(True)
        self.progress.setValue(0)
        self.status_lbl.setText("  Analysis failed.")
        if hasattr(self, '_overlay') and self._overlay:
            self._overlay._finish()
        QMessageBox.critical(self, "Analysis Error", msg)

    def export_report(self):
        if not self._results:
            QMessageBox.information(self, "No Results", "Run an analysis first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", "HTML Files (*.html)")
        if not path:
            return
        r = self._results
        html = [
            f"<html><head><style>",
            f"body{{background:{DARK};color:{TEXT};font-family:Consolas,monospace;padding:30px;}}",
            f"h1{{color:{ACCENT};letter-spacing:4px;}}h2{{color:{AMBER};margin-top:30px;}}",
            f"table{{width:100%;border-collapse:collapse;margin:10px 0;}}",
            f"th{{background:{PANEL};color:{DIM};padding:8px;border:1px solid {BORDER};text-align:left;}}",
            f"td{{padding:7px;border:1px solid {BORDER};}}tr:nth-child(even){{background:{MID};}}",
            f".HIGH{{color:{GREEN};font-weight:bold;}}.MEDIUM{{color:{AMBER};}}.LOW{{color:{RED};}}",
            f"</style></head><body>",
            f"<h1>FORENSIX REPORT</h1>",
            f"<p>File: <b>{r['filepath']}</b><br>Generated: {datetime.now().isoformat()}</p>",
            f"<h2>HASHES</h2><table><tr><th>Algorithm</th><th>Value</th></tr>",
        ]
        for k, v in r["hashes"].items():
            html.append(f"<tr><td>{k}</td><td>{v}</td></tr>")
        html.append("</table><h2>ANOMALIES</h2><table>"
                    "<tr><th>Severity</th><th>Type</th><th>Offset</th><th>Detail</th></tr>")
        for a in r["anomalies"]:
            html.append(f"<tr><td class='{a['severity']}'>{a['severity']}</td>"
                        f"<td>{a['type']}</td><td>{a['offset']}</td><td>{a['detail']}</td></tr>")
        html.append("</table><h2>MAGIC HITS</h2><table>"
                    "<tr><th>Offset</th><th>Hex</th><th>Confidence</th><th>Type</th><th>Category</th></tr>")
        for h in r["magic_hits"]:
            html.append(f"<tr><td>{h['offset']}</td><td>{h['hex_offset']}</td>"
                        f"<td class='{h['confidence']}'>{h['confidence']}</td>"
                        f"<td>{h['name']}</td><td>{h['category']}</td></tr>")
        html.append("</table></body></html>")
        with open(path, "w") as f:
            f.write("\n".join(html))
        self.status_lbl.setText(f"  Report saved: {path}")
        QMessageBox.information(self, "Export Complete", f"Report saved:\n{path}")


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
def main():
    import traceback as _tb

    def _excepthook(exc_type, exc_value, exc_tb):
        log_dir  = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else "."
        log_path = os.path.join(log_dir, "forensix_crash.log")
        msg      = "".join(_tb.format_exception(exc_type, exc_value, exc_tb))
        try:
            with open(log_path, "w") as f:
                f.write(msg)
        except Exception:
            pass
        try:
            box = QMessageBox()
            box.setWindowTitle("Forensix - Crash")
            box.setText(f"Unhandled error. Log written to:\n{log_path}")
            box.setDetailedText(msg)
            box.exec()
        except Exception:
            pass

    sys.excepthook = _excepthook
    app = QApplication(sys.argv)
    app.setApplicationName("Forensix")
    win = ForensixWindow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
