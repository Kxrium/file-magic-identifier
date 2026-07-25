"""
Signature database loading and matching.

Supports three source formats:
  - Native JSON  (data/signatures.json)  -- our own compact format
  - TrID-style XML definitions           (see parse_trid_xml)
  - Unix `file` magic database syntax    (see parse_unix_magic, subset)

Hex patterns may contain "??" as a wildcard byte, e.g. "52494646????????57415645"
matches RIFF....WAVE where the 4 middle bytes are ignored.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class Signature:
    hex: str                     # pattern, may contain "??" wildcard byte-pairs
    type: str                    # human readable file type
    offset: int = 0
    embeddable: bool = False     # worth searching for as an embedded blob
    note: str = ""

    def __post_init__(self):
        if len(self.hex) % 2 != 0:
            raise ValueError(f"Signature hex must have even length: {self.hex!r}")
        self._byte_pattern: List[Optional[int]] = []
        for i in range(0, len(self.hex), 2):
            pair = self.hex[i:i + 2]
            self._byte_pattern.append(None if pair == "??" else int(pair, 16))

    @property
    def length(self) -> int:
        return len(self._byte_pattern)

    @property
    def specificity(self) -> int:
        """Number of non-wildcard bytes -- used to rank overlapping matches."""
        return sum(1 for b in self._byte_pattern if b is not None)

    def match(self, data: bytes) -> Optional[float]:
        """
        Try to match this signature against `data` at self.offset.
        Returns a confidence score in (0, 1] on success, or None if it doesn't match.
        All non-wildcard bytes must match exactly; confidence reflects how
        much of the pattern is wildcarded (fully concrete patterns score 1.0).
        """
        start = self.offset
        end = start + self.length
        if end > len(data):
            return None
        window = data[start:end]
        for expected, actual in zip(self._byte_pattern, window):
            if expected is not None and expected != actual:
                return None
        if self.length == 0:
            return None
        # Confidence: concrete bytes count fully, wildcard bytes count half
        # (they matched trivially, so they add less evidentiary weight).
        wildcard_count = self.length - self.specificity
        score = (self.specificity + 0.5 * wildcard_count) / self.length
        return round(score, 3)

    def find_anywhere(self, data: bytes, max_hits: int = 5) -> List[int]:
        """Search for this signature anywhere in `data` (used for embedded-file
        detection). Only supports patterns without wildcards for speed."""
        if None in self._byte_pattern:
            return []
        needle = bytes(self._byte_pattern)
        hits = []
        start = 0
        while len(hits) < max_hits:
            idx = data.find(needle, start)
            if idx == -1:
                break
            hits.append(idx)
            start = idx + 1
        return hits


@dataclass
class Match:
    signature: Signature
    confidence: float


def load_json(path: str | Path) -> List[Signature]:
    raw = json.loads(Path(path).read_text())
    return [Signature(hex=e["hex"], type=e["type"], offset=e.get("offset", 0),
                       embeddable=e.get("embeddable", False), note=e.get("note", ""))
             for e in raw]


def parse_trid_xml(path: str | Path) -> List[Signature]:
    """
    Parse a simplified TrID-style XML definition file.

    Real TrID .trd definitions are a proprietary compiled binary format, so this
    parses the community-documented human-readable XML representation instead:

        <TrID>
          <Info><FileType>Example</FileType></Info>
          <FrontBlock>
            <Pattern Pos="0">4D5A</Pattern>
          </FrontBlock>
        </TrID>

    Each <Pattern> becomes one Signature. Multiple <TrID> root elements in one
    file (wrapped in <TrIDDefs>) are all parsed.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    defs = [root] if root.tag == "TrID" else list(root.findall("TrID"))
    sigs: List[Signature] = []
    for d in defs:
        info = d.find("Info")
        file_type = (info.findtext("FileType") if info is not None else None) or "Unknown (TrID)"
        for pattern in d.findall(".//Pattern"):
            hexval = (pattern.text or "").strip().replace(" ", "")
            if not hexval:
                continue
            pos = int(pattern.get("Pos", "0"))
            sigs.append(Signature(hex=hexval, type=file_type, offset=pos))
    return sigs


_MAGIC_LINE_RE = re.compile(
    r"^(?P<offset>\d+)\s+(?P<type>\S+)\s+(?P<test>\S+)\s+(?P<msg>.*)$"
)


def parse_unix_magic(path: str | Path) -> List[Signature]:
    """
    Parse a subset of the Unix `file`/`magic` database plain-text syntax:

        0   string   \\x89PNG\\r\\n\\x1a\\n   PNG image

    Supported: top-level (non-indented, non-continuation) lines with type
    `string` or `byte`/`short`/`long` given as a hex constant (0x..). Lines
    starting with '#' (comments) and '>' (continuation / AND-rules) are
    skipped -- full magic-file semantics (nested offsets, multi-level AND
    rules, indirect offsets) are out of scope for this lightweight parser.
    """
    sigs: List[Signature] = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if not line or line.startswith("#") or line.startswith(">"):
            continue
        m = _MAGIC_LINE_RE.match(line.strip())
        if not m:
            continue
        offset = int(m.group("offset"))
        mtype = m.group("type")
        test = m.group("test")
        msg = m.group("msg").strip()
        hexval = None
        if mtype == "string":
            hexval = _decode_escaped_string_to_hex(test)
        elif mtype in ("byte", "short", "long") and test.lower().startswith("0x"):
            val = test[2:]
            val = val.zfill(len(val) + (len(val) % 2))
            hexval = val
        if hexval:
            sigs.append(Signature(hex=hexval.upper(), type=msg or mtype, offset=offset))
    return sigs


def _decode_escaped_string_to_hex(token: str) -> str:
    """Turn a magic-file escaped string constant like \\x89PNG\\r\\n\\x1a\\n
    into a hex string."""
    raw = token.encode().decode("unicode_escape").encode("latin-1")
    return raw.hex()


def load_signatures(path: str | Path) -> List[Signature]:
    """Auto-detect format from file extension and load."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        return load_json(p)
    if p.suffix.lower() in (".xml",):
        return parse_trid_xml(p)
    return parse_unix_magic(p)


def best_matches(data: bytes, sigs: List[Signature], min_confidence: float = 0.0) -> List[Match]:
    """Return all matching signatures sorted by confidence (desc), then specificity."""
    out: List[Match] = []
    for s in sigs:
        conf = s.match(data)
        if conf is not None and conf >= min_confidence:
            out.append(Match(signature=s, confidence=conf))
    out.sort(key=lambda m: (m.confidence, m.signature.specificity), reverse=True)
    return out
