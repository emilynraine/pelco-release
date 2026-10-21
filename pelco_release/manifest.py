"""Strict JSON parsing and the manifest rules of spec sections 3 to 5."""
import json
import re

from jsonschema import Draft202012Validator, ValidationError, validators

from .codes import SPEC
from .crypto import encrypted_size


def _pattern(validator, pattern, instance, schema):
    # Python's `$` also matches before a final newline; a pattern's `$` must mean the end of the string.
    if pattern.endswith("$"):
        pattern = pattern[:-1] + r"\Z"
    if validator.is_type(instance, "string") and not re.search(pattern, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_Validator = validators.extend(Draft202012Validator, {"pattern": _pattern})


def _validator(name):
    with open(SPEC / "schema" / f"{name}.schema.json", encoding="utf-8") as f:
        return _Validator(json.load(f))


MANIFEST_SCHEMA = _validator("manifest")
SIGNATURE_SCHEMA = _validator("signature")
KEYRING_SCHEMA = _validator("keyring")


def _no_duplicates(pairs):
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("duplicate member name")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} isn't JSON")


class FloatLiteral:
    """A number written with a fraction or exponent: never equal to an integer, so `1.0` is not `1`."""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text


MAX_DEPTH = 32
MAX_VALUES = 4096


def _check_limits(doc):
    """At most MAX_VALUES values nested at most MAX_DEPTH deep, and no unpaired surrogates."""
    count = 0
    stack = [(doc, 1)]
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_VALUES:
            raise ValueError(f"more than {MAX_VALUES} values")
        if depth > MAX_DEPTH:
            raise ValueError(f"nested more than {MAX_DEPTH} deep")
        if isinstance(value, dict):
            for k, v in value.items():
                k.encode("utf-8")
                stack.append((v, depth + 1))
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, str):
            value.encode("utf-8")


def parse_json(data):
    """Strict JSON as spec section 3 requires. ValueError otherwise."""
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                         parse_constant=_no_constant, parse_float=FloatLiteral)
    except RecursionError:
        raise ValueError(f"nested more than {MAX_DEPTH} deep") from None
    _check_limits(doc)
    return doc


def dumps(doc):
    """How the tools write JSON. Readers never depend on it: signatures cover the stored bytes."""
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _unique(values):
    return len(values) == len(set(values))


def problems(manifest):
    """Every way the manifest breaks the schema or a cross-field rule; empty if it's valid."""
    found = [e.message for e in MANIFEST_SCHEMA.iter_errors(manifest)]
    if found:
        return found
    if not manifest["component"].startswith(manifest["product"] + "."):
        found.append("component doesn't start with the product")
    payload = manifest["payload"]
    if not _unique([p["name"] for p in payload]):
        found.append("payload names aren't unique")
    encrypted = [p for p in payload if "encryption" in p]
    if not _unique([p["encryption"]["nonce_prefix"] for p in encrypted]):
        found.append("nonce prefixes aren't unique")
    for p in encrypted:
        if p["size"] != encrypted_size(p["plain_size"], p["encryption"]["chunk_size"]):
            found.append(f"{p['name']}: size doesn't match plain_size and chunk_size")
    if not _unique([r["key_id"] for r in manifest.get("recipients", [])]):
        found.append("recipient key IDs aren't unique")
    return found
