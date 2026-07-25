from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import containers, report
from .console import print_results
from .scanner import FileResult, scan_directory, scan_file
from .signatures import load_signatures


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="magic-identifier",
                                  description="Identify files by content, not extension.")
    ap.add_argument("target", help="File or directory to scan")
    ap.add_argument("--db", default=str(Path(__file__).parent.parent / "data" / "signatures.json"),
                     help="Signature database (.json native, .xml TrID-style, or Unix magic text)")
    ap.add_argument("--hash", action="store_true", help="Compute MD5/SHA-256 for each file")
    ap.add_argument("--embedded", action="store_true",
                     help="Search for embedded ZIP/PDF/PE/PNG/JPEG blobs inside each file")
    ap.add_argument("--archive-recurse", action="store_true",
                     help="List contents of ZIP archives recursively (zips-within-zips)")
    ap.add_argument("--workers", type=int, default=8, help="Thread pool size for directory scans")
    ap.add_argument("--json", metavar="PATH", help="Export results as JSON")
    ap.add_argument("--csv", metavar="PATH", help="Export results as CSV")
    ap.add_argument("--html", metavar="PATH", help="Export results as an HTML report")
    ap.add_argument("--no-color", action="store_true", help="Force plain-text output (no rich table)")
    ap.add_argument("--mismatches-only", action="store_true",
                     help="Only print files whose detected type doesn't match their extension")
    ap.add_argument("--no-progress", action="store_true",
                     help="Disable the progress bar during directory scans")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        sigs = load_signatures(args.db)
    except Exception as e:  # noqa: BLE001
        print(f"error: could not load signature database '{args.db}': {e}", file=sys.stderr)
        return 2
    if not sigs:
        print(f"error: signature database '{args.db}' loaded zero signatures", file=sys.stderr)
        return 2

    target = Path(args.target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2

    if target.is_dir():
        results = scan_directory(target, sigs, do_hash=args.hash, do_embedded=args.embedded,
                                  workers=args.workers, show_progress=not args.no_progress)
    else:
        results = [scan_file(target, sigs, do_hash=args.hash, do_embedded=args.embedded)]

    if args.mismatches_only:
        results = [r for r in results if r.mismatch]

    if args.archive_recurse:
        _print_archive_contents(results)

    print_results(results, show_hashes=args.hash, show_embedded=args.embedded,
                  force_plain=args.no_color)

    for fmt, path, exporter in (
        ("JSON", args.json, report.export_json),
        ("CSV", args.csv, report.export_csv),
        ("HTML", args.html, report.export_html),
    ):
        if not path:
            continue
        try:
            exporter(results, path)
            print(f"\nWrote {fmt} report to {path}")
        except OSError as e:
            print(f"error: could not write {fmt} report to '{path}': {e}", file=sys.stderr)

    errors = sum(1 for r in results if r.error)
    return 1 if errors else 0


def _print_archive_contents(results: list[FileResult]) -> None:
    for r in results:
        if r.extension == ".zip" or "ZIP" in r.detected_type or "DOCX" in r.detected_type \
                or "XLSX" in r.detected_type or "JAR" in r.detected_type or "APK" in r.detected_type:
            members = list(containers.iter_archive_members(r.path))
            if members:
                print(f"\n{r.path} contains {len(members)} entries:")
                for name, depth in members[:200]:
                    print(f"  {'  ' * depth}{name}")


if __name__ == "__main__":
    raise SystemExit(main())
