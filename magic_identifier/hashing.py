import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def hash_file(path: str | Path) -> dict:
    """Stream a file once, computing MD5 and SHA-256 together."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
