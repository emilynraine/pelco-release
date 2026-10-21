"""Semantic Versioning 2.0.0 precedence, without build metadata."""
import re

_IDENT = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-({_IDENT}(?:\.{_IDENT})*))?")


def parse(version):
    """(major, minor, patch, pre-release identifiers or None); ValueError if not semver."""
    m = PATTERN.fullmatch(version) if isinstance(version, str) else None
    if not m:
        raise ValueError(f"not a semantic version: {version!r}")
    pre = m.group(4).split(".") if m.group(4) else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _compare_identifier(a, b):
    a_num, b_num = a.isdigit(), b.isdigit()
    if a_num and b_num:
        a, b = int(a), int(b)
    elif a_num != b_num:
        return -1 if a_num else 1
    return (a > b) - (a < b)


def compare(a, b):
    """-1, 0 or 1 as version a has lower, equal or higher precedence than b."""
    *a_core, a_pre = parse(a)
    *b_core, b_pre = parse(b)
    if a_core != b_core:
        return -1 if a_core < b_core else 1
    if a_pre is None or b_pre is None:
        return (a_pre is None) - (b_pre is None)
    for x, y in zip(a_pre, b_pre):
        if c := _compare_identifier(x, y):
            return c
    return (len(a_pre) > len(b_pre)) - (len(a_pre) < len(b_pre))
