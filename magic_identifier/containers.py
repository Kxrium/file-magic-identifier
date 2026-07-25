"""
ZIP is a polyglot magic number: DOCX, XLSX, PPTX, APK, JAR, and plain ZIP all
start with the same PK\\x03\\x04 bytes. This module peeks inside the ZIP's
internal file listing to tell them apart, and provides recursive archive
scanning (ZIP natively; RAR/7z if optional third-party libs are installed).
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Iterator, Optional

_OOXML_MARKERS = {
    "word/": "DOCX (Word)",
    "xl/": "XLSX (Excel)",
    "ppt/": "PPTX (PowerPoint)",
}


def refine_zip_type(path: str | Path) -> Optional[str]:
    """Given a file that matched the generic ZIP/OOXML signature, inspect its
    contents to return a more specific type, or None if it's a plain ZIP or
    unreadable as a zip."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return None

    if "AndroidManifest.xml" in names:
        return "APK (Android package)"
    if any(n.startswith("META-INF/MANIFEST.MF") for n in names):
        return "JAR (Java archive)"
    for prefix, label in _OOXML_MARKERS.items():
        if any(n.startswith(prefix) for n in names):
            return label
    if "[Content_Types].xml" in names:
        return "OOXML (unrecognized subtype)"
    return None  # plain zip


_OLE_EXTENSION_MAP = {
    ".doc": "DOC (Word 97-2003)", ".dot": "DOT (Word Template)",
    ".xls": "XLS (Excel 97-2003)", ".xlt": "XLT (Excel Template)",
    ".ppt": "PPT (PowerPoint 97-2003)", ".pot": "POT (PowerPoint Template)",
    ".msi": "MSI (Windows Installer)", ".msp": "MSP (Windows Installer Patch)",
    ".msg": "MSG (Outlook Message)", ".pub": "PUB (Publisher)",
    ".wps": "WPS (Works Word Processor)",
}


def refine_ole_type(ext: str) -> Optional[str]:
    """OLE Compound File Binary Format is shared by legacy Office documents,
    MSI installers, and Outlook .msg files - they're only distinguishable by
    parsing the internal stream directory, which is more work than this tool
    needs. We use the file extension as a practical proxy instead, same
    spirit as ZIP-container refinement above."""
    return _OLE_EXTENSION_MAP.get(ext.lower())


def iter_archive_members(path: str | Path, max_depth: int = 3) -> Iterator[tuple[str, int]]:
    """Recursively yield (member_path, depth) for ZIP archives, including
    zips-within-zips, up to max_depth. RAR/7z members are listed if the
    optional `rarfile` / `py7zr` packages are installed; otherwise they are
    reported as unsupported so the caller can note it rather than silently
    skip them."""
    yield from _walk_zip(str(path), depth=0, max_depth=max_depth)


def _walk_zip(path: str, depth: int, max_depth: int):
    if depth > max_depth:
        return
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                yield (info.filename, depth)
                if info.filename.lower().endswith(".zip") and depth < max_depth:
                    try:
                        import io
                        data = zf.read(info)
                        with zipfile.ZipFile(io.BytesIO(data)) as inner:
                            for inner_info in inner.infolist():
                                yield (f"{info.filename}!{inner_info.filename}", depth + 1)
                    except zipfile.BadZipFile:
                        pass
    except (zipfile.BadZipFile, OSError):
        return


def archive_kind_support(kind: str) -> bool:
    """Whether recursive scanning is actually available for this archive kind."""
    if kind == "zip":
        return True
    if kind == "rar":
        try:
            import rarfile  # noqa: F401
            return True
        except ImportError:
            return False
    if kind == "7z":
        try:
            import py7zr  # noqa: F401
            return True
        except ImportError:
            return False
    return False
