"""Checks a release in the order of spec section 7 and reports the first failure's result code."""
import hashlib
import re
from dataclasses import dataclass, field
from decimal import Decimal

from . import container, crypto, semver
from .codes import Rejected
from .manifest import KEYRING_SCHEMA, SIGNATURE_SCHEMA, parse_json, problems

VERIFIER, HOST, INSTALLER = "verifier", "host", "installer"
LAST_STEP = {VERIFIER: 5, HOST: 12, INSTALLER: 14}


@dataclass
class Context:
    """What the party checking the release knows. Only `checks` and the keyring matter to a verifier."""
    checks: str = INSTALLER
    accept_test: bool = False
    component: str | None = None
    hardware: str | None = None
    route: str | None = None
    installed: dict = field(default_factory=lambda: {"unit": {}, "system": {}})
    payload_types: frozenset = frozenset()
    recipient_keys: dict = field(default_factory=dict)  # key_id -> X25519 private key bytes
    reinstall: bool = False
    allow_downgrade: bool = False

    @classmethod
    def from_json(cls, doc, recipient_keys=None):
        """A context from its JSON form (see vectors/README.md); private keys are passed separately."""
        known = {"checks", "accept_test", "component", "hardware", "route", "installed",
                 "payload_types", "reinstall", "allow_downgrade"}
        ctx = cls(**{k: v for k, v in doc.items() if k in known})
        ctx.installed = {"unit": dict(ctx.installed.get("unit", {})),
                         "system": dict(ctx.installed.get("system", {}))}
        ctx.payload_types = frozenset(ctx.payload_types)
        ctx.recipient_keys = dict(recipient_keys or {})
        if ctx.checks not in LAST_STEP:
            raise ValueError(f"checks must be one of {sorted(LAST_STEP)}")
        return ctx


@dataclass
class Result:
    code: str
    detail: str = ""
    manifest: dict | None = None


def load_keyring(doc):
    """key_id -> keyring entry. ValueError if the keyring breaks its schema."""
    errors = [e.message for e in KEYRING_SCHEMA.iter_errors(doc)]
    if errors:
        raise ValueError(f"keyring: {errors[0]}")
    return {k["key_id"]: k for k in doc["keys"]}


_TIME = re.compile(r"([0-9-]{10}T[0-9:]{8})(?:\.([0-9]+))?Z")


def _instant(timestamp):
    m = _TIME.fullmatch(timestamp)
    return m.group(1), Decimal("0." + (m.group(2) or "0"))


def _version_known(v):
    try:
        semver.parse(v)
        return True
    except ValueError:
        return False


def check(stream, keyring, ctx, writer=None):
    """Checks the release read from `stream`.

    `writer`, if given, receives each payload's decrypted bytes: begin(payload), write(bytes), then
    commit() once every check has passed or abort() on any failure.
    """
    try:
        manifest = _check(stream, keyring, ctx, writer)
    except Rejected as r:
        if writer:
            writer.abort()
        return Result(r.code, r.detail)
    if writer:
        writer.commit()
    return Result("OK", manifest=manifest)


def _check(stream, keyring, ctx, writer):
    reader = container.Reader(stream)

    # 1. Container
    manifest_bytes = _leading_entry(reader, "manifest.json", container.MANIFEST_MAX)
    signature_bytes = _leading_entry(reader, "manifest.sig", container.SIGNATURE_MAX)

    # 2. Signature
    try:
        signatures = parse_json(signature_bytes)
    except ValueError as e:
        raise Rejected("SIGNATURE_MALFORMED", str(e)) from None
    if error := next(SIGNATURE_SCHEMA.iter_errors(signatures), None):
        raise Rejected("SIGNATURE_MALFORMED", error.message)
    known = [s for s in signatures["signatures"] if s["key_id"] in keyring]
    if not known:
        raise Rejected("KEY_UNKNOWN")
    signers = [keyring[s["key_id"]] for s in known
               if crypto.verify(manifest_bytes, bytes.fromhex(s["sig"]),
                                bytes.fromhex(keyring[s["key_id"]]["public_key"]))]
    if not signers:
        raise Rejected("SIGNATURE_INVALID")

    # 3. Format
    try:
        manifest = parse_json(manifest_bytes)
    except ValueError as e:
        raise Rejected("MANIFEST_INVALID", str(e)) from None
    if not isinstance(manifest, dict):
        raise Rejected("MANIFEST_INVALID", "not a JSON object")
    version_ = manifest.get("format_version")
    if manifest.get("format") != "pelco-release" or type(version_) is not int or version_ != 1:
        raise Rejected("FORMAT_UNSUPPORTED")

    # 4. Manifest
    if found := problems(manifest):
        raise Rejected("MANIFEST_INVALID", found[0])

    # 5. Key permission
    built_at = _instant(manifest["build"]["built_at"])
    if not any(manifest["channel"] in k["channels"] and manifest["product"] in k["products"]
               and ("not_after" not in k or built_at <= _instant(k["not_after"]))
               for k in signers):
        raise Rejected("KEY_NOT_PERMITTED")
    if LAST_STEP[ctx.checks] == 5:
        return manifest

    # 6. Channel
    if manifest["channel"] == "test" and not ctx.accept_test:
        raise Rejected("CHANNEL_NOT_ALLOWED")
    # 7. Target
    if manifest["component"] != ctx.component:
        raise Rejected("WRONG_COMPONENT")
    # 8. Hardware
    if ctx.hardware not in manifest["hardware"]:
        raise Rejected("HARDWARE_INCOMPATIBLE")
    # 9. Route
    if ctx.route not in manifest["routes"]:
        raise Rejected("ROUTE_NOT_ALLOWED")

    # 10. Requirements
    for r in manifest.get("requires", []):
        installed = ctx.installed[r["scope"]].get(r["component"])
        if (installed is None or not _version_known(installed)
                or ("min" in r and semver.compare(installed, r["min"]) < 0)
                or ("max_exclusive" in r and semver.compare(installed, r["max_exclusive"]) >= 0)):
            raise Rejected("REQUIREMENT_NOT_MET", f"{r['component']} ({r['scope']}) is {installed}")

    # 11. Version: an unknown installed version passes, so a unit that can't report one can be recovered.
    current = ctx.installed["unit"].get(manifest["component"])
    if current is not None and _version_known(current):
        order = semver.compare(manifest["version"], current)
        if order == 0 and not ctx.reinstall:
            raise Rejected("ALREADY_INSTALLED")
        if order < 0 and not ctx.allow_downgrade:
            raise Rejected("DOWNGRADE_NOT_ALLOWED")

    # 12. Payload types
    for p in manifest["payload"]:
        if p["type"] not in ctx.payload_types:
            raise Rejected("PAYLOAD_TYPE_UNSUPPORTED", p["type"])
    if LAST_STEP[ctx.checks] == 12:
        return manifest

    # 13. Recipient
    content_key = None
    if any("encryption" in p for p in manifest["payload"]):
        held = [r for r in manifest["recipients"] if r["key_id"] in ctx.recipient_keys]
        if not held:
            raise Rejected("NO_RECIPIENT_KEY")
        failure = None
        for r in held:
            try:
                content_key = crypto.unwrap(r, ctx.recipient_keys[r["key_id"]])
                break
            except Rejected as e:
                failure = e
        if content_key is None:
            raise failure

    # 14. Payload
    for p in manifest["payload"]:
        _payload(reader, p, content_key, writer)
    if reader.next_entry() is not None:
        raise Rejected("RELEASE_MALFORMED", "an entry follows the last payload")
    return manifest


def _leading_entry(reader, name, limit):
    entry = reader.next_entry()
    if entry is None or entry[0] != name:
        raise Rejected("RELEASE_MALFORMED", f"{name} isn't where it should be")
    if entry[1] > limit:
        raise Rejected("RELEASE_MALFORMED", f"{name} is over {limit} bytes")
    return reader.read_all()


def _payload(reader, p, content_key, writer):
    entry = reader.next_entry()
    if entry is None or entry[0] != p["name"]:
        raise Rejected("RELEASE_MALFORMED", f"expected payload {p['name']}")
    if entry[1] != p["size"]:
        raise Rejected("PAYLOAD_SIZE_MISMATCH", p["name"])
    stored_hash = hashlib.sha256()
    plain_hash = hashlib.sha256()
    enc = p.get("encryption")
    decryptor = enc and crypto.Decryptor(content_key, bytes.fromhex(enc["nonce_prefix"]),
                                         enc["chunk_size"], p["plain_size"])
    if writer:
        writer.begin(p)

    def emit(plain):
        plain_hash.update(plain)
        if writer and plain:
            writer.write(plain)

    while data := reader.read():
        stored_hash.update(data)
        emit(decryptor.update(data) if decryptor else data)
    if stored_hash.hexdigest() != p["sha256"]:
        raise Rejected("PAYLOAD_HASH_MISMATCH", p["name"])
    if decryptor:
        emit(decryptor.finish())
        if plain_hash.hexdigest() != p["plain_sha256"]:
            raise Rejected("PLAIN_HASH_MISMATCH", p["name"])
