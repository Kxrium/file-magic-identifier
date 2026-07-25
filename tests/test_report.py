import csv
import json

from magic_identifier import report
from magic_identifier.scanner import scan_directory


def test_export_json_roundtrip(sample_dir, sigs, tmp_path):
    results = scan_directory(sample_dir, sigs)
    out = tmp_path / "sub" / "report.json"  # nested, non-existent dir on purpose
    report.export_json(results, out)
    data = json.loads(out.read_text())
    assert len(data) == len(results)
    assert {"path", "detected_type", "confidence", "mismatch"} <= data[0].keys()


def test_export_csv_roundtrip(sample_dir, sigs, tmp_path):
    results = scan_directory(sample_dir, sigs)
    out = tmp_path / "sub" / "report.csv"
    report.export_csv(results, out)
    with open(out, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(results)


def test_export_html_contains_mismatch_badge(sample_dir, sigs, tmp_path):
    results = scan_directory(sample_dir, sigs)
    out = tmp_path / "sub" / "report.html"
    report.export_html(results, out)
    html = out.read_text()
    assert "MISMATCH" in html
    assert "trojan.pdf" in html
