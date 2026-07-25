from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import containers, text_types
from .hashing import hash_file
from .signatures import Signature, best_matches

HEADER_READ = 4096          # baseline bytes read for header signature matching
_header_read_cache: dict[int, int] = {}


def _header_read_size(sigs: List[Signature]) -> int:
    """How many bytes to read from the front of a file so every loaded
    signature (including ones with a large offset, like ISO 9660's magic
    number at byte 32769) actually gets checked. Cached per signature-list
    identity so we're not recomputing this on every single file."""
    key = id(sigs)
    cached = _header_read_cache.get(key)
    if cached is not None:
        return cached
    needed = HEADER_READ
    for s in sigs:
        needed = max(needed, s.offset + s.length)
    _header_read_cache[key] = needed
    return needed
EMBEDDED_SCAN_CAP = 20 * 1024 * 1024  # don't full-scan files bigger than this for embedded content

# Extensions we "expect" for a given detected type, used for mismatch detection.
EXPECTED_EXTENSIONS = {
    "JPEG": {".jpg", ".jpeg"},
    "PNG": {".png"},
    "PDF": {".pdf"},
    "PE EXE/DLL": {".exe", ".dll", ".sys", ".ocx"},
    "ELF": {"", ".so", ".bin", ".elf", ".out"},
    "RAR": {".rar"},
    "RAR5": {".rar"},
    "7-Zip": {".7z"},
    "GIF": {".gif"},
    "BMP": {".bmp"},
    "ICO": {".ico"},
    "PSD": {".psd"},
    "GZIP": {".gz", ".tgz"},
    "BZIP2": {".bz2"},
    "XZ": {".xz"},
    "TAR (POSIX ustar)": {".tar"},
    "TAR (GNU ustar)": {".tar"},
    "SQLite DB": {".db", ".sqlite", ".sqlite3"},
    "Java Class File": {".class"},
    "ISO 9660 Image": {".iso"},
    "WAV": {".wav"},
    "AVI": {".avi"},
    "Matroska/WebM (MKV)": {".mkv", ".webm"},
    "MP3 (ID3)": {".mp3"},
    "MP3 (no ID3)": {".mp3"},
    "MP4/M4A/MOV (ftyp box)": {".mp4", ".m4a", ".mov", ".m4v"},
    "TrueType Font (TTF)": {".ttf"},
    "TrueType Font (true)": {".ttf"},
    "OpenType Font (OTF)": {".otf"},
    "WOFF Font": {".woff"},
    "WOFF2 Font": {".woff2"},
    "DOCX (Word)": {".docx", ".docm"},
    "XLSX (Excel)": {".xlsx", ".xlsm"},
    "PPTX (PowerPoint)": {".pptx", ".pptm"},
    "APK (Android package)": {".apk"},
    "JAR (Java archive)": {".jar"},
    "ZIP/OOXML": {".zip"},
    "DOC (Word 97-2003)": {".doc"}, "DOT (Word Template)": {".dot"},
    "XLS (Excel 97-2003)": {".xls"}, "XLT (Excel Template)": {".xlt"},
    "PPT (PowerPoint 97-2003)": {".ppt"}, "POT (PowerPoint Template)": {".pot"},
    "MSI (Windows Installer)": {".msi"}, "MSP (Windows Installer Patch)": {".msp"},
    "MSG (Outlook Message)": {".msg"}, "PUB (Publisher)": {".pub"},
    "WPS (Works Word Processor)": {".wps"},
    "WEBP": {".webp"},
    "Windows Shortcut (LNK)": {".lnk"},
    "VirtualBox Disk Image (VDI)": {".vdi"},
}


@dataclass
class FileResult:
    path: str
    detected_type: str
    confidence: float
    extension: str
    mismatch: bool
    md5: str = ""
    sha256: str = ""
    embedded_findings: List[str] = field(default_factory=list)
    alt_matches: List[str] = field(default_factory=list)
    error: Optional[str] = None


EXTENSION_ONLY_FALLBACK = {
    ".pyc": "Python bytecode (compiled)",  # magic number changes every Python version
    ".pyo": "Python bytecode (optimized)",
}


def detect_header(data: bytes, sigs: List[Signature]) -> tuple[str, float, List[str]]:
    """Return (best_type, confidence, [other candidate labels])."""
    matches = best_matches(data, sigs)
    if not matches:
        return "Unknown", 0.0, []
    top = matches[0]
    alts = [f"{m.signature.type} ({m.confidence:.0%})" for m in matches[1:4]]
    return top.signature.type, top.confidence, alts


def find_embedded(data: bytes, sigs: List[Signature]) -> List[str]:
    """Search for embeddable signatures anywhere past the start of the file
    (skipping a match at offset 0, which is just the file's own header)."""
    findings = []
    for s in sigs:
        if not s.embeddable:
            continue
        for idx in s.find_anywhere(data):
            if idx == 0:
                continue
            findings.append(f"{s.type} at offset {idx}")
    return findings


def scan_file(
    path: str | Path,
    sigs: List[Signature],
    do_hash: bool = False,
    do_embedded: bool = False,
) -> FileResult:
    path = Path(path)
    ext = path.suffix.lower()
    try:
        with open(path, "rb") as f:
            header = f.read(_header_read_size(sigs))
    except OSError as e:
        return FileResult(path=str(path), detected_type="Error", confidence=0.0,
                           extension=ext, mismatch=False, error=str(e))

    detected, confidence, alts = detect_header(header, sigs)

    if detected == "Unknown":
        text_label = text_types.sniff_text_type(header, path.name)
        if text_label:
            detected, confidence = text_label, 1.0
        elif ext in EXTENSION_ONLY_FALLBACK:
            detected, confidence = EXTENSION_ONLY_FALLBACK[ext], 0.5  # extension-only guess, not content-verified

    if detected == "ZIP/OOXML":
        refined = containers.refine_zip_type(path)
        if refined:
            detected = refined

    if detected == "OLE Compound File":
        refined = containers.refine_ole_type(ext)
        if refined:
            detected = refined

    expected = EXPECTED_EXTENSIONS.get(detected)
    mismatch = bool(expected) and ext not in expected and detected not in ("Unknown",)

    result = FileResult(
        path=str(path), detected_type=detected, confidence=confidence,
        extension=ext, mismatch=mismatch, alt_matches=alts,
    )

    if do_hash:
        try:
            h = hash_file(path)
            result.md5, result.sha256 = h["md5"], h["sha256"]
        except OSError as e:
            result.error = f"hash error: {e}"

    if do_embedded:
        try:
            size = path.stat().st_size
            if size <= EMBEDDED_SCAN_CAP:
                with open(path, "rb") as f:
                    full = f.read()
                result.embedded_findings = find_embedded(full, sigs)
            else:
                result.embedded_findings = [f"(skipped, file > {EMBEDDED_SCAN_CAP // (1024*1024)}MB)"]
        except OSError as e:
            result.error = (result.error + "; " if result.error else "") + f"embedded scan error: {e}"

    return result


def scan_directory(
    root: str | Path,
    sigs: List[Signature],
    do_hash: bool = False,
    do_embedded: bool = False,
    workers: int = 8,
    show_progress: bool = False,
    progress_callback=None,
) -> List[FileResult]:
    """Multi-threaded recursive directory scan. I/O-bound work (reading files,
    hashing) benefits from threads even under the GIL since most time is
    spent waiting on disk reads.

    show_progress=True prints a live progress bar (via rich if available,
    otherwise a periodic "N / total" line) as files complete -- handy for
    large folders where the scan would otherwise look like it's hung.

    progress_callback, if given, is called as progress_callback(done, total)
    after every completed file. This is how non-console UIs (e.g. a Tkinter
    GUI) hook in their own progress bar instead of the console one.
    """
    paths: List[Path] = []
    for dp, _, fs in os.walk(root):
        for fn in fs:
            paths.append(Path(dp) / fn)

    total = len(paths)
    results: List[FileResult] = []

    progress_ctx = _make_progress(total) if show_progress else None
    task_id = None
    if progress_ctx is not None:
        progress_ctx.__enter__()
        task_id = progress_ctx.add_task("Scanning", total=total)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(scan_file, p, sigs, do_hash, do_embedded): p
                for p in paths
            }
            done = 0
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001 - keep scanning even if one file explodes
                    p = futures[fut]
                    results.append(FileResult(path=str(p), detected_type="Error",
                                               confidence=0.0, extension=p.suffix.lower(),
                                               mismatch=False, error=str(e)))
                done += 1
                if progress_ctx is not None:
                    progress_ctx.update(task_id, advance=1)
                elif show_progress and (done % 200 == 0 or done == total):
                    print(f"\r{done}/{total} files scanned...", end="", flush=True)
                if progress_callback is not None:
                    progress_callback(done, total)
    finally:
        if progress_ctx is not None:
            progress_ctx.__exit__(None, None, None)
        elif show_progress:
            print()  # newline after the plain-text counter

    results.sort(key=lambda r: r.path)
    return results


def _make_progress(total: int):
    """Return a rich Progress context manager, or None if rich isn't installed
    (caller falls back to the plain periodic-print counter)."""
    try:
        from rich.progress import (BarColumn, Progress, TextColumn,
                                    TimeRemainingColumn, MofNCompleteColumn)
    except ImportError:
        return None
    return Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
    )
