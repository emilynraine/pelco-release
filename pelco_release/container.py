"""The release file: an uncompressed POSIX ustar archive of regular files (spec section 2)."""
import re

from .codes import Rejected

BLOCK = 512
ZERO_BLOCK = bytes(BLOCK)
END = bytes(2 * BLOCK)
NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
MANIFEST_MAX = 65536
SIGNATURE_MAX = 8192


def header(name, size, typeflag=b"0"):
    """A ustar header with fixed metadata, so the same entries always give the same bytes."""
    h = bytearray(BLOCK)

    def put(offset, data):
        h[offset:offset + len(data)] = data

    put(0, name.encode("ascii"))
    put(100, b"0000644\0")
    put(108, b"0000000\0")
    put(116, b"0000000\0")
    put(124, b"%011o\0" % size)
    put(136, b"00000000000\0")
    put(148, b" " * 8)
    put(156, typeflag)
    put(257, b"ustar\0")
    put(263, b"00")
    put(329, b"0000000\0")
    put(337, b"0000000\0")
    put(148, b"%06o\0 " % sum(h))
    return bytes(h)


def entry(name, data):
    if not NAME.fullmatch(name):
        raise ValueError(f"bad entry name {name!r}")
    return header(name, len(data)) + data + bytes(-len(data) % BLOCK)


def pack(entries):
    """entries: (name, bytes) pairs, in order."""
    return b"".join(entry(name, data) for name, data in entries) + END


def _malformed(detail):
    return Rejected("RELEASE_MALFORMED", detail)


def _octal(field):
    text = field.rstrip(b"\0 ").lstrip(b" ")
    if not text or any(c not in b"01234567" for c in text):
        raise _malformed("bad number in an entry header")
    return int(text, 8)


def _parse(h):
    if _octal(h[148:156]) != sum(h[:148]) + 8 * ord(" ") + sum(h[156:]):
        raise _malformed("entry header checksum doesn't match")
    if h[257:263] != b"ustar\0" or h[263:265] != b"00":
        raise _malformed("entry header isn't POSIX ustar")
    if h[156:157] not in (b"0", b"\0"):
        raise _malformed("entry isn't a regular file")
    if h[345] != 0:
        raise _malformed("entry name uses the ustar prefix")
    try:
        name = h[0:100].split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        raise _malformed("entry name isn't ASCII") from None
    if not NAME.fullmatch(name):
        raise _malformed(f"bad entry name {name!r}")
    return name, _octal(h[124:136])


class Reader:
    """Reads a release file as a stream, one entry at a time."""

    def __init__(self, stream):
        self._stream = stream
        self._left = 0
        self._pad = 0

    def _exact(self, n):
        parts = []
        while n:
            data = self._stream.read(n)
            if not data:
                raise _malformed("the file ends early")
            parts.append(data)
            n -= len(data)
        return b"".join(parts)

    def next_entry(self):
        """(name, size) of the next entry, or None at the end of the archive."""
        while self._left:
            self.read()
        self._exact(self._pad)
        self._pad = 0
        block = self._exact(BLOCK)
        if block == ZERO_BLOCK:
            if self._exact(BLOCK) != ZERO_BLOCK:
                raise _malformed("broken end-of-archive marker")
            while data := self._stream.read(65536):
                if data.count(0) != len(data):
                    raise _malformed("data after the end of the archive")
            return None
        name, size = _parse(block)
        self._left = size
        self._pad = -size % BLOCK
        return name, size

    def read(self, n=65536):
        """Up to n bytes of the current entry; b"" once it's all read."""
        if not self._left:
            return b""
        data = self._exact(min(n, self._left))
        self._left -= len(data)
        return data

    def read_all(self):
        parts = []
        while data := self.read():
            parts.append(data)
        return b"".join(parts)
