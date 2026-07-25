from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import List

from .scanner import FileResult

_HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Magic Identifier Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0e0f11; color:#e6e6e6; }}
h1 {{ font-size: 1.4rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; }}
th, td {{ padding: 6px 10px; border-bottom: 1px solid #2a2c30; text-align: left; }}
th {{ background: #17181b; position: sticky; top:0; }}
tr.mismatch {{ background: #3a1f1f; }}
tr.unknown td:nth-child(2) {{ color: #888; }}
.badge {{ padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; }}
.badge.mismatch {{ background:#7a2222; color:#fff; }}
.small {{ color:#999; font-size:0.75rem; }}
</style></head><body>
<h1>Magic Identifier Report</h1>
<p class="small">{count} files scanned. {mismatch_count} extension mismatch(es) found.</p>
<table>
<tr><th>Path</th><th>Detected Type</th><th>Confidence</th><th>Extension</th><th>Mismatch</th><th>MD5</th><th>SHA-256</th><th>Embedded / Notes</th></tr>
{rows}
</table>
</body></html>
"""


def _rows_as_dicts(results: List[FileResult]) -> List[dict]:
    return [asdict(r) for r in results]


def export_json(results: List[FileResult], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(_rows_as_dicts(results), indent=2))


def export_csv(results: List[FileResult], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["path", "detected_type", "confidence", "extension", "mismatch",
              "md5", "sha256", "embedded_findings", "alt_matches", "error"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = asdict(r)
            row["embedded_findings"] = "; ".join(row["embedded_findings"])
            row["alt_matches"] = "; ".join(row["alt_matches"])
            writer.writerow(row)


def export_html(results: List[FileResult], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for r in results:
        cls = "mismatch" if r.mismatch else ("unknown" if r.detected_type == "Unknown" else "")
        badge = '<span class="badge mismatch">MISMATCH</span>' if r.mismatch else ""
        notes = ", ".join(r.embedded_findings) if r.embedded_findings else (r.error or "")
        rows.append(
            f'<tr class="{cls}"><td>{_esc(r.path)}</td><td>{_esc(r.detected_type)}</td>'
            f'<td>{r.confidence:.0%}</td><td>{_esc(r.extension)}</td>'
            f'<td>{badge}</td><td class="small">{r.md5}</td><td class="small">{r.sha256}</td>'
            f'<td class="small">{_esc(notes)}</td></tr>'
        )
    html = _HTML_TEMPLATE.format(
        count=len(results),
        mismatch_count=sum(1 for r in results if r.mismatch),
        rows="\n".join(rows),
    )
    Path(out_path).write_text(html)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
