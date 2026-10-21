"""Builds, signs and packs releases."""
import hashlib
import os

from . import container, crypto
from .manifest import parse_json

DEFAULT_CHUNK_SIZE = 4096
FIELD_ORDER = ["format", "format_version", "product", "component", "version", "reported_version",
               "channel", "hardware", "requires", "routes", "payload", "recipients", "build"]
PRIVATE_KEY_FORMAT = "pelco-release-private-key"


def build(fields, payloads, recipients=(), random_bytes=os.urandom):
    """A manifest and its payload entries.

    fields: every manifest field except `payload` and `recipients`.
    payloads: dicts with `name`, `type` and `data` (the plain image), and optionally `encrypt` and
    `chunk_size`.
    recipients: (key_id, X25519 public key) pairs; required if any payload is encrypted.
    Returns (manifest dict, [(entry name, stored bytes)]).
    """
    encrypting = any(p.get("encrypt") for p in payloads)
    if encrypting and not recipients:
        raise ValueError("encrypted payloads need at least one recipient")
    content_key = random_bytes(32) if encrypting else None
    prefixes = set()
    described, entries = [], []
    for p in payloads:
        plain = p["data"]
        item = {"name": p["name"], "type": p["type"]}
        if p.get("encrypt"):
            chunk_size = p.get("chunk_size", DEFAULT_CHUNK_SIZE)
            while (prefix := random_bytes(8)) in prefixes:
                pass
            prefixes.add(prefix)
            stored = crypto.encrypt(content_key, prefix, chunk_size, plain)
            item.update(size=len(stored), sha256=hashlib.sha256(stored).hexdigest(),
                        encryption={"alg": crypto.ENCRYPTION_ALG, "chunk_size": chunk_size,
                                    "nonce_prefix": prefix.hex()},
                        plain_size=len(plain), plain_sha256=hashlib.sha256(plain).hexdigest())
        else:
            stored = plain
            item.update(size=len(stored), sha256=hashlib.sha256(stored).hexdigest())
        described.append(item)
        entries.append((p["name"], stored))

    manifest = dict(fields, payload=described)
    if encrypting:
        manifest["recipients"] = [crypto.wrap(content_key, key_id, public, random_bytes)
                                  for key_id, public in recipients]
    ordered = {k: manifest[k] for k in FIELD_ORDER if k in manifest}
    ordered.update((k, v) for k, v in manifest.items() if k not in ordered)
    return ordered, entries


def signature_file(manifest_bytes, signers, existing=None):
    """manifest.sig with a signature from each (key_id, Ed25519 private key), added to `existing`."""
    doc = existing or {"format": "pelco-release-signature", "format_version": 1, "signatures": []}
    for key_id, private in signers:
        doc["signatures"] = [s for s in doc["signatures"] if s["key_id"] != key_id]
        doc["signatures"].append({"key_id": key_id, "alg": crypto.SIGNATURE_ALG,
                                  "sig": crypto.sign(manifest_bytes, private).hex()})
    return doc


def pack(manifest_bytes, signature_bytes, entries):
    return container.pack([("manifest.json", manifest_bytes), ("manifest.sig", signature_bytes),
                           *entries])


def private_key_file(key_id, alg, private):
    return {"format": PRIVATE_KEY_FORMAT, "format_version": 1, "key_id": key_id, "alg": alg,
            "private_key": private.hex()}


def load_private_key(data, alg):
    """(key_id, private key bytes) from a private key file's bytes."""
    doc = parse_json(data)
    if doc.get("format") != PRIVATE_KEY_FORMAT or doc.get("alg") != alg:
        raise ValueError(f"not a pelco-release {alg} private key")
    private = bytes.fromhex(doc["private_key"])
    if len(private) != 32:
        raise ValueError("private key isn't 32 bytes")
    return doc["key_id"], private

