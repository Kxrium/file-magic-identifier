"""
Plain-text source files (.py, .java, ...) have no magic bytes, so binary
signature matching can never identify them. If the header sniff comes back
Unknown, we fall back to: is this decodable as text? If so, use the
extension (and a couple of shebang/marker heuristics) to label it.
"""

CODE_EXTENSIONS = {
    ".py": "Python source",
    ".java": "Java source",
    ".c": "C source",
    ".h": "C header",
    ".cpp": "C++ source",
    ".hpp": "C++ header",
    ".cs": "C# source",
    ".js": "JavaScript source",
    ".ts": "TypeScript source",
    ".jsx": "JSX source",
    ".tsx": "TSX source",
    ".go": "Go source",
    ".rs": "Rust source",
    ".rb": "Ruby source",
    ".php": "PHP source",
    ".swift": "Swift source",
    ".kt": "Kotlin source",
    ".sh": "Shell script",
    ".bash": "Bash script",
    ".pl": "Perl source",
    ".lua": "Lua source",
    ".sql": "SQL source",
    ".html": "HTML document",
    ".htm": "HTML document",
    ".css": "CSS stylesheet",
    ".json": "JSON data",
    ".xml": "XML document",
    ".yaml": "YAML data",
    ".yml": "YAML data",
    ".md": "Markdown document",
    ".txt": "Plain text",
    ".csv": "CSV data",
    ".ipynb": "Jupyter Notebook (JSON)",
    ".drawio": "draw.io Diagram (XML)",
    ".vbox": "VirtualBox Machine Config (XML)",
    ".log": "Log file (text)",
    ".ini": "INI config file",
    ".cfg": "Config file (text)",
    ".conf": "Config file (text)",
    ".toml": "TOML config",
    ".ico": "ICO",  # only reached if the binary ICO signature didn't match
    ".svg": "SVG image (XML)",
    ".gitignore": "Git ignore rules (text)",
    ".env": "Environment/config file (text)",
    ".ps1": "PowerShell script",
    ".bat": "Batch script",
    ".cmd": "Batch script",
}

# Filenames that pathlib treats as having NO suffix because the whole name
# starts with a dot (e.g. ".env" -> Path(".env").suffix == ""). Matched on
# the full filename instead of the extension.
DOTFILE_NAMES = {
    ".env": "Environment/config file (text)",
    ".gitignore": "Git ignore rules (text)",
    ".gitattributes": "Git attributes (text)",
    ".editorconfig": "Editor config (text)",
    ".npmrc": "npm config (text)",
    ".flake8": "Flake8 config (text)",
}

_SPECIAL_SUFFIXES = {
    ".vbox-prev": "VirtualBox Machine Config backup (XML)",
}

_SHEBANGS = {
    "python": "Python source",
    "bash": "Bash script",
    "sh": "Shell script",
    "perl": "Perl source",
    "ruby": "Ruby source",
    "node": "JavaScript source",
}


def sniff_text_type(sample: bytes, filename: str) -> str | None:
    """Return a label for a text file, or None if it doesn't look like text
    or isn't a recognized code/text extension. `filename` is the file's full
    name (not the whole path) so dotfiles like ".env" can be matched even
    though pathlib reports them as having no suffix."""
    text = _decode_text(sample)
    if text is None:
        return None

    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.startswith("#!"):
        for key, label in _SHEBANGS.items():
            if key in first_line:
                return f"{label} (shebang)"

    if filename in DOTFILE_NAMES:
        return DOTFILE_NAMES[filename]

    lower = filename.lower()
    for suffix, label in _SPECIAL_SUFFIXES.items():
        if lower.endswith(suffix):
            return label

    suffix = "." + filename.split(".")[-1] if "." in filename else ""
    return CODE_EXTENSIONS.get(suffix.lower())


def _decode_text(sample: bytes) -> str | None:
    """Try UTF-8 first (the common case), then UTF-16 with BOM (Windows
    sometimes saves .ini/.xml/config files this way), else give up."""
    try:
        return sample.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if sample.startswith(b"\xff\xfe"):
        try:
            return sample.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    if sample.startswith(b"\xfe\xff"):
        try:
            return sample.decode("utf-16-be")
        except UnicodeDecodeError:
            return None
    return None
