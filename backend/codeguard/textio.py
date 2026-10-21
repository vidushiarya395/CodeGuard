"""Reading source files whatever their encoding, the way Python itself would.

Order: a byte-order mark (UTF-8, UTF-16, UTF-32), then a PEP 263 coding line
(# -*- coding: latin-1 -*-), then UTF-8. Bytes that do not decode are replaced, never fatal.
"""

from __future__ import annotations

import codecs
import io
import re
import tokenize

_CODING = re.compile(rb"^[ \t\f]*#.*?coding[:=]")  # PEP 263
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),  # before UTF-16: the UTF-32 LE mark starts with the UTF-16 LE one
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def decode_source(data: bytes) -> tuple[str, str | None]:
    """(text, note). The note says how the file was read when it was not plain UTF-8, or what was
    wrong with it; None for an ordinary UTF-8 file."""
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            text = data.decode(encoding, errors="replace")
            return text, None if encoding == "utf-8-sig" else f"read as {encoding.upper()} (byte-order mark)"
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except SyntaxError as exc:
        text = data.decode("utf-8", errors="replace")
        if any(_CODING.match(line) for line in data.splitlines()[:2]):
            return text, f"its coding declaration is not valid ({exc}); read as UTF-8"
        return text, "some bytes are not valid UTF-8 and were replaced"
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        text = data.decode(encoding, errors="replace")
        return text, f"some bytes are not valid {encoding.upper()} and were replaced"
    except LookupError:
        return data.decode("utf-8", errors="replace"), f"unknown encoding {encoding!r}; read as UTF-8"
    if encoding.lower().replace("_", "-") in ("utf-8", "utf-8-sig"):
        return text, None
    return text, f"read as {encoding} (coding declaration)"


def read_source(path) -> tuple[str, str | None]:
    with open(path, "rb") as fh:
        return decode_source(fh.read())
