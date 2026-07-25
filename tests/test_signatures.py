from pathlib import Path

from magic_identifier.signatures import (
    Signature,
    best_matches,
    parse_trid_xml,
    parse_unix_magic,
)


def test_exact_match():
    sig = Signature(hex="25504446", type="PDF", offset=0)
    assert sig.match(b"%PDFrest") == 1.0


def test_no_match():
    sig = Signature(hex="25504446", type="PDF", offset=0)
    assert sig.match(b"not a pdf") is None


def test_wildcard_match():
    sig = Signature(hex="52494646????????57415645", type="WAV", offset=0)
    data = b"RIFF" + b"\x00\x00\x00\x00" + b"WAVEfmt "
    conf = sig.match(data)
    assert conf is not None
    assert 0 < conf < 1.0  # wildcards reduce confidence below a fully concrete match


def test_wildcard_still_requires_concrete_bytes():
    sig = Signature(hex="52494646????????57415645", type="WAV", offset=0)
    data = b"RIFF" + b"\x00\x00\x00\x00" + b"XXXXfmt "  # wrong concrete bytes at the end
    assert sig.match(data) is None


def test_offset_respected():
    sig = Signature(hex="4344303031", type="ISO", offset=32769)
    data = b"\x00" * 32769 + bytes.fromhex("4344303031")
    assert sig.match(data) == 1.0
    assert sig.match(b"\x00" * 5) is None  # too short for offset+length


def test_best_matches_ranks_by_confidence_then_specificity():
    concrete = Signature(hex="4D5A", type="EXE", offset=0)
    wildcard = Signature(hex="4D??", type="Vague", offset=0)
    data = b"MZ\x90\x00"
    matches = best_matches(data, [wildcard, concrete])
    assert matches[0].signature.type == "EXE"  # fully concrete match ranked first


def test_find_anywhere_embedded():
    sig = Signature(hex="504B0304", type="ZIP", offset=0, embeddable=True)
    data = b"junk" * 10 + bytes.fromhex("504B0304") + b"more"
    hits = sig.find_anywhere(data)
    assert hits == [40]


def test_parse_trid_xml(tmp_path):
    xml = tmp_path / "defs.trid.xml"
    xml.write_text(
        "<TrIDDefs><TrID><Info><FileType>Windows Executable</FileType></Info>"
        "<FrontBlock><Pattern Pos=\"0\">4D5A</Pattern></FrontBlock></TrID></TrIDDefs>"
    )
    sigs = parse_trid_xml(xml)
    assert len(sigs) == 1
    assert sigs[0].type == "Windows Executable"
    assert sigs[0].hex == "4D5A"
    assert sigs[0].offset == 0


def test_parse_unix_magic(tmp_path):
    magic_file = tmp_path / "sample.magic"
    magic_file.write_text(
        "# comment line, should be skipped\n"
        "0\tstring\t\\x89PNG\\r\\n\\x1a\\n\tPNG image data\n"
        "257\tstring\tustar\tPOSIX tar archive\n"
    )
    sigs = parse_unix_magic(magic_file)
    types = {s.type: s for s in sigs}
    assert "PNG image data" in types
    assert types["PNG image data"].hex == "89504E470D0A1A0A"
    assert types["PNG image data"].offset == 0
    assert "POSIX tar archive" in types
    assert types["POSIX tar archive"].offset == 257


def test_json_db_loads_and_matches_real_files(sigs):
    matches = best_matches(bytes.fromhex("89504e470d0a1a0a") + b"rest", sigs)
    assert matches
    assert matches[0].signature.type == "PNG"
