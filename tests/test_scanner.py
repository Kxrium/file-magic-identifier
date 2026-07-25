from magic_identifier.containers import iter_archive_members, refine_zip_type
from magic_identifier.scanner import scan_directory, scan_file


def test_detects_true_type_for_valid_files(sample_dir, sigs):
    r = scan_file(sample_dir / "photo.jpg", sigs)
    assert r.detected_type == "JPEG"
    assert not r.mismatch


def test_flags_extension_mismatch(sample_dir, sigs):
    r = scan_file(sample_dir / "trojan.pdf", sigs)
    assert r.detected_type == "PE EXE/DLL"
    assert r.mismatch is True


def test_no_false_mismatch_for_matching_extension(sample_dir, sigs):
    r = scan_file(sample_dir / "doc.pdf", sigs)
    assert r.detected_type == "PDF"
    assert r.mismatch is False


def test_unknown_binary_is_not_flagged_as_mismatch(sample_dir, sigs):
    r = scan_file(sample_dir / "readme.txt", sigs)
    # readme.txt is plain text -> falls back to text-type sniffing, not "Unknown"
    assert r.detected_type in ("Plain text", "Unknown")
    assert r.mismatch is False


def test_code_file_detected_via_shebang(sample_dir, sigs):
    r = scan_file(sample_dir / "script.py", sigs)
    assert "Python" in r.detected_type


def test_docx_refined_from_generic_zip(sample_dir, sigs):
    r = scan_file(sample_dir / "report.docx", sigs)
    assert r.detected_type == "DOCX (Word)"
    assert not r.mismatch


def test_refine_zip_type_direct(sample_dir):
    assert refine_zip_type(sample_dir / "report.docx") == "DOCX (Word)"
    assert refine_zip_type(sample_dir / "nested.zip") is None  # plain zip, no OOXML markers


def test_hashing_produces_stable_digests(sample_dir, sigs):
    r1 = scan_file(sample_dir / "doc.pdf", sigs, do_hash=True)
    r2 = scan_file(sample_dir / "doc.pdf", sigs, do_hash=True)
    assert r1.sha256 == r2.sha256
    assert len(r1.sha256) == 64
    assert len(r1.md5) == 32


def test_embedded_detection_finds_nested_zip(sample_dir, sigs):
    r = scan_file(sample_dir / "nested.zip", sigs, do_embedded=True)
    # the outer zip's own header matches at offset 0 (excluded); the inner
    # zip's local file header should show up as an embedded finding
    assert any("offset" in f for f in r.embedded_findings)


def test_archive_recursion_lists_nested_members(sample_dir):
    members = list(iter_archive_members(sample_dir / "nested.zip"))
    names = [n for n, _depth in members]
    assert "top.txt" in names
    assert "inner.zip" in names
    assert any(n.startswith("inner.zip!") for n in names)


def test_directory_scan_covers_all_files(sample_dir, sigs):
    results = scan_directory(sample_dir, sigs)
    scanned_names = {r.path.split("/")[-1] for r in results}
    assert "photo.jpg" in scanned_names
    assert "trojan.pdf" in scanned_names
    mismatches = [r for r in results if r.mismatch]
    assert any(r.path.endswith("trojan.pdf") for r in mismatches)


def test_directory_scan_with_progress_bar_still_returns_all_results(sample_dir, sigs, capsys):
    results = scan_directory(sample_dir, sigs, show_progress=True)
    scanned_names = {r.path.split("/")[-1] for r in results}
    assert "photo.jpg" in scanned_names
    assert len(results) == len(list(sample_dir.iterdir()))


def test_missing_file_reports_error_not_crash(tmp_path, sigs):
    r = scan_file(tmp_path / "does_not_exist.bin", sigs)
    assert r.error is not None
    assert r.detected_type == "Error"


def test_new_signature_types_detected(sample_dir, sigs):
    assert scan_file(sample_dir / "img.bmp", sigs).detected_type == "BMP"
    assert scan_file(sample_dir / "sound.wav", sigs).detected_type == "WAV"
    assert scan_file(sample_dir / "font.ttf", sigs).detected_type == "TrueType Font (TTF)"
    assert scan_file(sample_dir / "db.sqlite", sigs).detected_type == "SQLite DB"
    assert scan_file(sample_dir / "app.class", sigs).detected_type == "Java Class File"
    assert scan_file(sample_dir / "archive.tar", sigs).detected_type == "TAR (POSIX ustar)"


def test_large_offset_signature_is_actually_checked(tmp_path, sigs):
    """Regression test: HEADER_READ used to be a fixed 4096 bytes, which is
    smaller than the ISO 9660 signature's offset (32769), so ISO files were
    always reported Unknown. The header read size must scale to cover it."""
    iso = tmp_path / "disk.iso"
    iso.write_bytes(b"\x00" * 32769 + bytes.fromhex("4344303031") + b"pad")
    r = scan_file(iso, sigs)
    assert r.detected_type == "ISO 9660 Image"


def test_ole_compound_file_refined_by_extension(tmp_path, sigs):
    ole_header = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 40
    cases = {
        "old.doc": "DOC (Word 97-2003)",
        "old.ppt": "PPT (PowerPoint 97-2003)",
        "old.xls": "XLS (Excel 97-2003)",
        "setup.msi": "MSI (Windows Installer)",
    }
    for name, expected in cases.items():
        (tmp_path / name).write_bytes(ole_header)
        r = scan_file(tmp_path / name, sigs)
        assert r.detected_type == expected, f"{name}: got {r.detected_type!r}"
        assert not r.mismatch


def test_webp_and_lnk_and_vdi_signatures(tmp_path, sigs):
    (tmp_path / "a.webp").write_bytes(
        bytes.fromhex("52494646") + b"\x24\x00\x00\x00" + bytes.fromhex("57454250") + b"rest"
    )
    assert scan_file(tmp_path / "a.webp", sigs).detected_type == "WEBP"

    (tmp_path / "a.lnk").write_bytes(
        bytes.fromhex("4C0000000114020000000000C000000000000046") + b"rest"
    )
    assert scan_file(tmp_path / "a.lnk", sigs).detected_type == "Windows Shortcut (LNK)"

    (tmp_path / "a.vdi").write_bytes(b"<<< Oracle VM VirtualBox Disk Image >>>\n" + b"\x00" * 10)
    assert scan_file(tmp_path / "a.vdi", sigs).detected_type == "VirtualBox Disk Image (VDI)"


def test_dotfile_env_detected_despite_no_pathlib_suffix(tmp_path, sigs):
    (tmp_path / ".env").write_bytes(b"API_KEY=abc123\nDEBUG=true\n")
    r = scan_file(tmp_path / ".env", sigs)
    assert "Environment" in r.detected_type


def test_ipynb_and_drawio_and_vbox_detected(tmp_path, sigs):
    (tmp_path / "nb.ipynb").write_bytes(b'{"cells": [], "metadata": {}}')
    assert scan_file(tmp_path / "nb.ipynb", sigs).detected_type == "Jupyter Notebook (JSON)"

    (tmp_path / "d.drawio").write_bytes(b"<mxfile></mxfile>")
    assert scan_file(tmp_path / "d.drawio", sigs).detected_type == "draw.io Diagram (XML)"

    (tmp_path / "m.vbox").write_bytes(b'<?xml version="1.0"?><VirtualBox/>')
    assert scan_file(tmp_path / "m.vbox", sigs).detected_type == "VirtualBox Machine Config (XML)"


def test_utf16_bom_text_file_detected(tmp_path, sigs):
    content = b"\xff\xfe" + "[.ShellClassInfo]\r\nIconResource=x.dll".encode("utf-16-le")
    (tmp_path / "desktop.ini").write_bytes(content)
    r = scan_file(tmp_path / "desktop.ini", sigs)
    assert r.detected_type == "INI config file"


def test_pyc_extension_only_fallback(tmp_path, sigs):
    (tmp_path / "mod.cpython-312.pyc").write_bytes(bytes.fromhex("cb0d0d0a") + b"\x00" * 10)
    r = scan_file(tmp_path / "mod.cpython-312.pyc", sigs)
    assert r.detected_type == "Python bytecode (compiled)"
    assert r.confidence < 1.0  # extension-only guess, lower confidence than a real content match
