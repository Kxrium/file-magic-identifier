import io
import zipfile

import pytest

from magic_identifier.signatures import load_json


@pytest.fixture(scope="session")
def sigs():
    return load_json("data/signatures.json")


@pytest.fixture()
def sample_dir(tmp_path):
    """Populate tmp_path with one sample file per interesting case."""
    files = {
        "photo.jpg": bytes.fromhex("ffd8ffe0") + b"jpegbytes",
        "logo.png": bytes.fromhex("89504e470d0a1a0a") + b"pngbytes",
        "doc.pdf": bytes.fromhex("25504446") + b"1.4 pdfbytes",
        "readme.txt": b"just plain text, nothing special",
        "script.py": b'#!/usr/bin/env python\nprint("hello")\n',
        "trojan.pdf": bytes.fromhex("4d5a9000") + b"actually an exe",   # mismatch
        "archive.tar": b"x" * 257 + b"ustar\x0000" + b"y" * 300,
        "img.bmp": bytes.fromhex("424d") + b"\x00" * 20,
        "sound.wav": (bytes.fromhex("52494646") + b"\x24\x00\x00\x00"
                       + bytes.fromhex("57415645") + b"fmt data..."),
        "font.ttf": bytes.fromhex("0001000000") + b"fontbytes",
        "db.sqlite": bytes.fromhex("53514c69746520666f726d6174203300") + b"\x00" * 20,
        "app.class": bytes.fromhex("cafebabe") + b"\x00\x00\x003",
    }
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)

    # A real DOCX (zip containing word/document.xml)
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<document/>")
    (tmp_path / "report.docx").write_bytes(docx_buf.getvalue())

    # A ZIP with an embedded ZIP inside it (for embedded/recursive tests)
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as inner:
        inner.writestr("deep.txt", "deep contents")
    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as outer:
        outer.writestr("top.txt", "top contents")
        outer.writestr("inner.zip", inner_buf.getvalue())
    (tmp_path / "nested.zip").write_bytes(outer_buf.getvalue())

    return tmp_path
