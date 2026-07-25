# File Magic Identifier

A lightweight file-signature (magic byte) scanner built for spotting
disguised or mislabeled files , the kind of technique used in malware
triage and DFIR to catch payloads hiding behind a fake extension
(`invoice.pdf` that's actually a PE executable, a `.jpg` with an embedded
ZIP appended after the image data, etc).

## Why this matters for security work
- **Extension spoofing detection** — flags any file whose real content
  doesn't match what its name claims
- **Embedded payload detection** — finds file signatures hiding *inside*
  another file, not just at byte 0 (a common technique for smuggling a
  second payload past a casual look)
- **SHA-256/MD5 hashing** built in, for cross-referencing against
  VirusTotal/known-hash databases
- **Bulk triage** — multi-threaded recursive scanning of an entire
  directory tree with a single command

## Quick start
pip install -r requirements.txt
python gui.py              # point-and-click, no command line needed
or
python -m magic_identifier C:\path\to\folder --hash --embedded


Identify what a file *actually is* by inspecting its bytes, instead of trusting
its extension.

```
python3 -m magic_identifier /path/to/scan --hash --embedded


## Features

- **Extension mismatch detection** — flags files whose content doesn't match
  their extension (e.g. `invoice.pdf` that's actually a Windows EXE).
- **Confidence scoring** — signatures with wildcard bytes score below a fully
  concrete match; when several signatures match, the best-ranked one wins and
  runners-up are listed as alternates.
- **Wildcard bytes** — signatures can use `??` for "any byte", e.g.
  `52494646????????57415645` matches `RIFF....WAVE` regardless of the 4-byte
  chunk size in the middle.
- **Three signature database formats**:
  - native JSON (`data/signatures.json`)
  - TrID-style XML definitions (`--db defs.trid.xml`) — see caveat below
  - a subset of the Unix `file`/`magic` plain-text syntax (`--db magic.txt`)
- **Multi-threaded directory scanning** (`--workers N`, default 8), with a
  live progress bar (`--no-progress` to disable).
- **MD5 / SHA-256 hashing** of every file (`--hash`).
- **Embedded file detection** — finds ZIP/PDF/PNG/JPEG/PE/ELF signatures
  hiding *inside* a larger file, not just at offset 0 (`--embedded`).
- **Recursive archive scanning** — lists ZIP contents recursively, including
  zips-within-zips (`--archive-recurse`). RAR/7z member listing works too if
  the optional `rarfile` / `py7zr` packages are installed.
- **ZIP-container disambiguation** — DOCX, XLSX, PPTX, JAR, and APK all share
  the ZIP magic number; the tool peeks at the internal file listing
  (`word/`, `xl/`, `AndroidManifest.xml`, `META-INF/MANIFEST.MF`, ...) to
  report the real type.
- **Rich colored terminal output** (falls back to plain text automatically if
  `rich` isn't installed, or with `--no-color`).
- **Export to JSON, CSV, and HTML** (`--json out.json --csv out.csv --html out.html`).
- **Unit tests** with generated sample files covering every feature (`pytest`).

### Extended signature set

Beyond the original JPEG/PNG/PDF/ZIP/PE/ELF/RAR, the database now covers:
MP4/MOV/M4A, WAV, AVI, MKV/WebM, GIF, BMP, ICO, PSD, TTF/OTF/WOFF/WOFF2 fonts,
SQLite databases, Java `.class` files, ISO 9660 images, GZIP/BZIP2/XZ/TAR,
7-Zip, WEBP, Windows `.lnk` shortcuts, VirtualBox `.vdi` disk images, and —
via container inspection — DOCX, XLSX, PPTX, JAR, APK (ZIP-based), and legacy
`.doc`/`.ppt`/`.xls`/`.msi`/`.msg` (OLE Compound File-based).

**Plain-text and config files** (`.py`, `.java`, `.js`, `.ipynb`, `.drawio`,
`.vbox`, `.ini`, `.env`, dotfiles like `.gitignore`, and more) have no magic
bytes at all. When header sniffing comes back `Unknown`, the tool checks
whether the content decodes as text — UTF-8, or UTF-16 with a BOM (common
for Windows `.ini`/config files) — and labels it from its filename (or a `#!`
shebang line when present) instead of reporting a false "Unknown". A small
number of extensions with no reliable content signature at all (like `.pyc`,
whose magic number changes every Python version) fall back to an
extension-only guess, flagged with reduced confidence. See
`magic_identifier/text_types.py` for the full map.

**Note on header read size**: signature offsets can be large (ISO 9660's
marker sits at byte 32769), so the tool reads however many bytes the loaded
signature database actually needs, not a fixed small chunk — otherwise
far-offset signatures would silently never match.

## GUI (no command line needed)

If you'd rather not use the terminal, there's a point-and-click interface:

```
python gui.py
```

It opens a window where you can:
- **Browse...** to pick a folder
- check boxes for hashing / embedded-file search
- use the **Show:** dropdown to filter the table to All files / Mismatches
  only / Unknown only / Mismatches + Unknown
- click **Scan Folder** and watch a live progress bar
- see results in a sortable table, with extension mismatches highlighted in red
- click **Export HTML/CSV/JSON Report...** to save a report — **exports use
  whatever filter is currently selected**, so you can generate separate
  reports for e.g. mismatches-only and the full scan just by changing the
  dropdown and exporting again each time. The suggested filename reflects
  the filter (`..._full`, `..._mismatches`, `..._unknown`, etc.) so it's easy
  to tell them apart later.

This only needs the Python standard library (`tkinter`, included with the
standard Windows/macOS Python installer) — no extra `pip install` beyond
what's already in `requirements.txt`.

## Usage (command line)

```
python3 -m magic_identifier TARGET [options]

  TARGET                  a single file or a directory to scan recursively

  --db PATH               signature database (default: data/signatures.json)
                          .json -> native format, .xml -> TrID-style,
                          anything else -> Unix magic syntax
  --hash                  compute MD5 + SHA-256 for each file
  --embedded              search for embedded ZIP/PDF/PE/PNG/JPEG blobs
  --archive-recurse       list ZIP archive contents recursively
  --workers N             thread pool size for directory scans (default 8)
  --mismatches-only       only print files with an extension mismatch
  --no-progress           disable the progress bar during directory scans
  --no-color              force plain-text output
  --json PATH             export results as JSON
  --csv PATH              export results as CSV
  --html PATH             export results as a standalone HTML report
```

## Caveats

- **TrID definitions**: real TrID `.trd` files are a proprietary compiled
  binary format. This tool parses the community-documented human-readable XML
  representation instead (see `magic_identifier/signatures.py` docstring for
  the exact schema). Point `--db` at a real `.trd` file and it will fail to
  parse — convert it to the XML form first.
- **Unix magic syntax**: only single-line `string`/`byte`/`short`/`long`
  rules are supported. Multi-line `>` continuation rules (AND-logic,
  indirect offsets, nested tests) are skipped. This covers the common case
  of simple magic-number matching but is not a full `file(1)` reimplementation.
- **RAR/7z recursive scanning**: only member *listing* is available, and only
  if `rarfile` (RAR) or `py7zr` (7z) is installed — these aren't in
  `requirements.txt` by default since they pull in extra native dependencies.
  ZIP recursion works out of the box with the standard library.
- **Embedded-file scanning** reads the whole file into memory, so it's capped
  at 20 MB per file by default (`EMBEDDED_SCAN_CAP` in `scanner.py`) to avoid
  blowing up memory on huge files during a directory scan.
- **Confidence scores** are a heuristic (concrete bytes weight 1.0, wildcard
  bytes weight 0.5), not a statistical probability — treat them as a ranking
  signal between competing candidate signatures, not a calibrated percentage.

## Project layout

```
magic_identifier/
  __init__.py       public API (scan_file, scan_directory, Signature, ...)
  __main__.py        `python -m magic_identifier` entry point
  cli.py             argument parsing, orchestration
  signatures.py       Signature/Match dataclasses, wildcard matching,
                      confidence scoring, JSON/TrID/Unix-magic loaders
  scanner.py          per-file detection, extension-mismatch logic,
                      threaded directory walk, embedded-file search
  containers.py        ZIP container disambiguation (DOCX/XLSX/APK/JAR),
                      recursive archive member listing
  text_types.py         extension/shebang fallback for source & text files
  hashing.py             streaming MD5/SHA-256
  report.py               JSON/CSV/HTML exporters
  console.py               rich-based colored table, plain-text fallback
data/
  signatures.json     the default signature database
tests/
  conftest.py         generates sample binary fixtures on the fly
  test_signatures.py  wildcard matching, confidence scoring, parsers
  test_scanner.py     mismatch detection, hashing, embedded/archive scanning
  test_report.py      export format tests
```

Run the tests with:

```
pip install -r requirements.txt
pytest
```
