from __future__ import annotations

from typing import List

from .scanner import FileResult

try:
    from rich.console import Console
    from rich.table import Table
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False


def print_results(results: List[FileResult], show_hashes: bool = False,
                   show_embedded: bool = False, force_plain: bool = False) -> None:
    if _HAS_RICH and not force_plain:
        _print_rich(results, show_hashes, show_embedded)
    else:
        _print_plain(results, show_hashes, show_embedded)


def _print_rich(results, show_hashes, show_embedded):
    console = Console()
    table = Table(show_lines=False, header_style="bold cyan")
    table.add_column("Path", overflow="fold")
    table.add_column("Detected Type")
    table.add_column("Conf.", justify="right")
    table.add_column("Ext.")
    if show_hashes:
        table.add_column("SHA-256", overflow="fold")
    if show_embedded:
        table.add_column("Embedded")

    for r in results:
        if r.error:
            style = "red"
        elif r.mismatch:
            style = "bold yellow"
        elif r.detected_type == "Unknown":
            style = "dim"
        else:
            style = "green"

        type_cell = r.detected_type + ("  ⚠ MISMATCH" if r.mismatch else "")
        row = [r.path, type_cell, f"{r.confidence:.0%}", r.extension]
        if show_hashes:
            row.append(r.sha256[:16] + "…" if r.sha256 else "")
        if show_embedded:
            row.append(", ".join(r.embedded_findings) if r.embedded_findings else "")
        table.add_row(*row, style=style)

    console.print(table)
    mismatches = sum(1 for r in results if r.mismatch)
    console.print(f"[bold]{len(results)}[/bold] files scanned, "
                   f"[{'red' if mismatches else 'green'}]{mismatches} extension mismatch(es)[/].")


def _print_plain(results, show_hashes, show_embedded):
    for r in results:
        flag = " [MISMATCH]" if r.mismatch else ""
        line = f"{r.path}: {r.detected_type} ({r.confidence:.0%}) (ext {r.extension}){flag}"
        if show_hashes and r.sha256:
            line += f" sha256={r.sha256}"
        if show_embedded and r.embedded_findings:
            line += f" embedded=[{', '.join(r.embedded_findings)}]"
        if r.error:
            line += f" ERROR: {r.error}"
        print(line)
    mismatches = sum(1 for r in results if r.mismatch)
    print(f"\n{len(results)} files scanned, {mismatches} extension mismatch(es).")
