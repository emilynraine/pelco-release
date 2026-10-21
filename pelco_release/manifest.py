"""Strict JSON parsing and the manifest rules of spec sections 3 to 5."""
import json

from jsonschema import Draft202012Validator

from .codes import SPEC
from .crypto import encrypted_size


def _validator(name):
    with open(SPEC / "schema" / f"{name}.schema.json", encoding="utf-8") as f:
        return Draft202012Validator(json.load(f))


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


def parse_json(data):
    """UTF-8 without a BOM, no duplicate member names, no NaN or Infinity. ValueError otherwise."""
    return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                      parse_constant=_no_constant)


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
