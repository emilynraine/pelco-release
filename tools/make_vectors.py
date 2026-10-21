#!/usr/bin/env python3
"""Generates the conformance vectors in vectors/.

    python tools/make_vectors.py          write vectors/
    python tools/make_vectors.py --check  confirm vectors/ matches this generator byte for byte,
                                          and the reference checker gives every case its result

Every random value comes from a seed per case, so the output only changes when this file does.
Each case has exactly one fault, so every conforming reader reports the same code.
"""
import argparse
import copy
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pelco_release import builder, container, crypto, verifier  # noqa: E402
from pelco_release.codes import NUMBERS  # noqa: E402
from pelco_release.manifest import MAX_DEPTH, MAX_VALUES, dumps, parse_json  # noqa: E402

OUT = ROOT / "vectors"
BUILT_AT = "2026-10-19T15:24:00Z"

SIGNING_KEYS = {
    "vec-release": {"channels": ["release"], "products": ["example"]},
    "vec-test": {"channels": ["test"], "products": ["example"]},
    "vec-other-product": {"channels": ["release", "test"], "products": ["other"]},
    "vec-until-build": {"channels": ["release"], "products": ["example"],
                        "not_after": "2026-10-19T15:24:00.000Z"},
    "vec-expired": {"channels": ["release"], "products": ["example"],
                    "not_after": "2026-10-19T15:23:59.999Z"},
}
UNKNOWN_SIGNER = "vec-unknown"
RECIPIENTS = ["vec-device", "vec-host"]
UNLISTED_RECIPIENT = "vec-other-device"

FIELDS = {
    "format": "pelco-release",
    "format_version": 1,
    "product": "example",
    "component": "example.unit.app",
    "version": "2.0.0",
    "reported_version": "V2.0.0 example",
    "channel": "release",
    "hardware": ["example-hw-a"],
    "requires": [
        {"component": "example.unit.boot", "scope": "unit", "min": "1.0.0"},
        {"component": "example.parent.app", "scope": "system", "min": "3.0.0",
         "max_exclusive": "4.0.0"},
    ],
    "routes": ["relay", "usb"],
    "build": {"source": "example-firmware@v2.0.0",
              "commit": "0123456789abcdef0123456789abcdef01234567", "built_at": BUILT_AT},
}

CONTEXT = {
    "checks": "installer",
    "accept_test": False,
    "component": "example.unit.app",
    "hardware": "example-hw-a",
    "route": "relay",
    "installed": {"unit": {"example.unit.app": "1.5.0", "example.unit.boot": "1.2.0"},
                  "system": {"example.parent.app": "3.1.0"}},
    "payload_types": ["raw-bin"],
    "recipient_keys": ["vec-device"],
    "reinstall": False,
    "allow_downgrade": False,
}


class Seeded:
    """Deterministic stand-in for os.urandom."""

    def __init__(self, label):
        self._label = label.encode()
        self._counter = 0

    def __call__(self, n):
        self._counter += 1
        return hashlib.shake_256(b"pelco-release vectors\0%s\0%d" % (self._label, self._counter)).digest(n)


def test_key(key_id):
    return hashlib.sha256(b"pelco-release test key\0" + key_id.encode()).digest()


def installed(unit=None, system=None):
    base = copy.deepcopy(CONTEXT["installed"])
    base["unit"].update(unit or {})
    base["system"].update(system or {})
    return base


def payload(rng, size=5000, encrypt=True, chunk_size=1024, name="app.bin", type_="raw-bin"):
    return {"name": name, "type": type_, "data": rng(size), "encrypt": encrypt,
            "chunk_size": chunk_size}


def make(rng, fields=None, payloads=None, recipients=RECIPIENTS):
    f = copy.deepcopy(FIELDS)
    f.update(fields or {})
    payloads = payloads if payloads is not None else [payload(rng)]
    keys = [(k, crypto.x25519_public(test_key(k))) for k in recipients]
    return builder.build(f, payloads, keys if any(p["encrypt"] for p in payloads) else [], rng)


def sig(manifest_bytes, signers=("vec-release",)):
    return dumps(builder.signature_file(manifest_bytes, [(k, test_key(k)) for k in signers]))


def signed(manifest, entries, signers=("vec-release",)):
    manifest_bytes = dumps(manifest)
    return builder.pack(manifest_bytes, sig(manifest_bytes, signers), entries)


def rehash(manifest, index, stored):
    manifest["payload"][index]["sha256"] = hashlib.sha256(stored).hexdigest()


def with_header(data, offset, change):
    """`data` with the entry header at `offset` changed, its checksum recomputed."""
    h = bytearray(data[offset:offset + container.BLOCK])
    change(h)
    h[148:156] = b" " * 8
    h[148:156] = b"%06o\0 " % sum(h)
    return data[:offset] + bytes(h) + data[offset + container.BLOCK:]


def add_member(manifest_bytes, member):
    """The manifest with `member` added as its first member, written as given."""
    return manifest_bytes.replace(b"{\n", b"{\n  " + member + b",\n", 1)


def at_limits(manifest_bytes, extra_depth=0, extra_values=0):
    """The manifest with unknown fields that bring it to exactly the JSON limits, plus any extra."""
    base = parse_json(manifest_bytes)
    nested = 0
    for _ in range(MAX_DEPTH - 2 + extra_depth):
        nested = [nested]
    base_count = 1 + sum(1 for _ in _values(base))
    filler = MAX_VALUES - base_count - 1 - (MAX_DEPTH - 1 + extra_depth) + extra_values
    member = (b'"future_deep": ' + json.dumps(nested, separators=(",", ":")).encode()
              + b', "future_filler": ' + json.dumps([0] * filler, separators=(",", ":")).encode())
    return add_member(manifest_bytes, member)


def _values(doc):
    children = doc.values() if isinstance(doc, dict) else doc if isinstance(doc, list) else []
    for child in children:
        yield child
        yield from _values(child)


def flip(data, index):
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1:]


CASES = []


def case(expected, description, **context):
    def register(fn):
        CASES.append({"name": fn.__name__.replace("_", "-"), "expected": expected,
                      "description": description, "context": context, "make": fn})
        return fn
    return register


# --- OK -------------------------------------------------------------------------------------------

@case("OK", "Encrypted payload in five chunks, the last one short.")
def ok_encrypted(rng):
    return signed(*make(rng))


@case("OK", "Unencrypted payload; the manifest has no recipients.")
def ok_plain(rng):
    return signed(*make(rng, payloads=[payload(rng, encrypt=False)]))


@case("OK", "Encrypted payload that fills its last chunk exactly.")
def ok_exact_chunks(rng):
    return signed(*make(rng, payloads=[payload(rng, size=4096)]))


@case("OK", "Encrypted payload smaller than one chunk.")
def ok_single_chunk(rng):
    return signed(*make(rng, payloads=[payload(rng, size=100)]))


@case("OK", "Three payloads: two encrypted with one content key and different nonce prefixes, one plain.")
def ok_three_payloads(rng):
    return signed(*make(rng, payloads=[
        payload(rng), payload(rng, size=3000, name="data.bin"),
        payload(rng, size=700, encrypt=False, name="extra.bin")]))


@case("OK", "Signed by a key the keyring doesn't know and by one it does.")
def ok_one_known_signer(rng):
    return signed(*make(rng), signers=(UNKNOWN_SIGNER, "vec-release"))


@case("OK", "Two known signatures, the first doesn't verify; one verifying signature is enough.")
def ok_one_of_two_verifies(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(b"other bytes", [("vec-release", test_key("vec-release"))])
    doc = builder.signature_file(manifest_bytes, [("vec-until-build", test_key("vec-until-build"))], doc)
    return builder.pack(manifest_bytes, dumps(doc), entries)


@case("OK", "Unknown fields at the top level, in a payload and in build are ignored.")
def ok_unknown_fields(rng):
    manifest, entries = make(rng)
    manifest["future_field"] = {"anything": [1, 2]}
    manifest["payload"][0]["future_field"] = True
    manifest["build"]["future_field"] = "x"
    return signed(manifest, entries)


@case("OK", "Strings and member names written with escapes are compared after unescaping.")
def ok_escaped_strings(rng):
    return with_manifest_bytes(rng, lambda b: b
                               .replace(b'"product": "example"', rb'"product": "\u0065xample"', 1)
                               .replace(b'"channel"', rb'"\u0063hannel"', 1))


@case("OK", "A number with a fraction and exponent in an unknown field.")
def ok_fraction_in_unknown_field(rng):
    return with_manifest_bytes(rng, lambda b: add_member(b, b'"future_field": -1.5e3'))


@case("OK", "Exactly 4 096 values, nested exactly 32 deep.")
def ok_json_limits(rng):
    return with_manifest_bytes(rng, lambda b: at_limits(b))


@case("OK", "A route the installer doesn't know is ignored.")
def ok_unknown_route(rng):
    return signed(*make(rng, fields={"routes": ["future-route", "relay"]}))


@case("OK", "Test release, installer configured for testing.", accept_test=True)
def ok_test_channel(rng):
    return signed(*make(rng, fields={"channel": "test", "version": "2.0.0-rc.1"}),
                  signers=("vec-test",))


@case("OK", "Same version installed; caller asked to reinstall.",
      installed=installed(unit={"example.unit.app": "2.0.0"}), reinstall=True)
def ok_reinstall(rng):
    return signed(*make(rng))


@case("OK", "Newer version installed; caller passed the downgrade flag.",
      installed=installed(unit={"example.unit.app": "2.1.0"}), allow_downgrade=True)
def ok_downgrade_allowed(rng):
    return signed(*make(rng))


@case("OK", "The target's installed version is unknown, so the version step passes.",
      installed={"unit": {"example.unit.boot": "1.2.0"}, "system": {"example.parent.app": "3.1.0"}})
def ok_installed_version_unknown(rng):
    return signed(*make(rng))


@case("OK", "2.0.0 is newer than the installed 2.0.0-rc.1.",
      installed=installed(unit={"example.unit.app": "2.0.0-rc.1"}))
def ok_newer_than_prerelease(rng):
    return signed(*make(rng))


@case("OK", "2.10.0 is newer than the installed 2.9.0: versions compare numerically.",
      installed=installed(unit={"example.unit.app": "2.9.0"}))
def ok_numeric_ordering(rng):
    return signed(*make(rng, fields={"version": "2.10.0"}))


@case("OK", "Requirements at their edges: min is inclusive, and 4.0.0-rc.1 is below max_exclusive 4.0.0.",
      installed=installed(unit={"example.unit.boot": "1.0.0"},
                          system={"example.parent.app": "4.0.0-rc.1"}))
def ok_requirement_edges(rng):
    return signed(*make(rng))


@case("OK", "Key not_after equals build.built_at, written with a fraction; not_after is inclusive.")
def ok_key_until_build(rng):
    return signed(*make(rng), signers=("vec-until-build",))


@case("OK", "A verifier stops after step 5, so the target, channel and recipient keys don't matter.",
      checks="verifier", component="example.unit.boot", recipient_keys=[])
def ok_verifier(rng):
    return signed(*make(rng))


@case("OK", "A host stops after step 12, so it needs no recipient key.",
      checks="host", recipient_keys=[])
def ok_host(rng):
    return signed(*make(rng))


@case("OK", "Zero blocks after the end-of-archive marker, as tar pads to its record size.")
def ok_archive_padding(rng):
    data = signed(*make(rng))
    return data + bytes(-len(data) % 10240)


# --- 1 RELEASE_MALFORMED --------------------------------------------------------------------------

@case("RELEASE_MALFORMED", "Empty file.")
def malformed_empty(rng):
    return b""


@case("RELEASE_MALFORMED", "manifest.sig comes before manifest.json.")
def malformed_signature_first(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    return container.pack([("manifest.sig", sig(manifest_bytes)), ("manifest.json", manifest_bytes),
                           *entries])


@case("RELEASE_MALFORMED", "No manifest.sig.")
def malformed_no_signature(rng):
    manifest, entries = make(rng)
    return container.pack([("manifest.json", dumps(manifest)), *entries])


@case("RELEASE_MALFORMED", "manifest.json is over 65 536 bytes, though validly signed.")
def malformed_manifest_too_large(rng):
    manifest, entries = make(rng)
    manifest["padding"] = "x" * 65536
    return signed(manifest, entries)


@case("RELEASE_MALFORMED", "manifest.sig is over 8 192 bytes.")
def malformed_signature_too_large(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(manifest_bytes, [("vec-release", test_key("vec-release"))])
    doc["padding"] = "x" * 8192
    return builder.pack(manifest_bytes, dumps(doc), entries)


@case("RELEASE_MALFORMED", "The payload entry is missing.")
def malformed_payload_missing(rng):
    manifest, _ = make(rng)
    return signed(manifest, [])


@case("RELEASE_MALFORMED", "The payload entry has a different name from the manifest's.")
def malformed_payload_renamed(rng):
    manifest, entries = make(rng)
    return signed(manifest, [("other.bin", entries[0][1])])


@case("RELEASE_MALFORMED", "Two payload entries in a different order from the manifest's.")
def malformed_payloads_reordered(rng):
    manifest, entries = make(rng, payloads=[payload(rng), payload(rng, name="data.bin")])
    return signed(manifest, entries[::-1])


@case("RELEASE_MALFORMED", "An extra entry after the last payload.")
def malformed_extra_entry(rng):
    manifest, entries = make(rng)
    return signed(manifest, [*entries, ("extra.bin", b"extra")])


@case("RELEASE_MALFORMED", "The payload entry is a symbolic link, not a regular file.")
def malformed_link_entry(rng):
    data = signed(*make(rng))
    offset = data.index(container.header("app.bin", 0)[:100])
    return with_header(data, offset, lambda h: h.__setitem__(slice(156, 157), b"2"))


@case("RELEASE_MALFORMED", "A pax extended header before manifest.json.")
def malformed_pax_header(rng):
    data = signed(*make(rng))
    record = b"11 path=x\n"
    pax = container.header("PaxHeader", len(record), b"x") + record + bytes(512 - len(record))
    return pax + data


@case("RELEASE_MALFORMED", "manifest.json's header has GNU tar's magic, not POSIX ustar.")
def malformed_gnu_magic(rng):
    return with_header(signed(*make(rng)), 0,
                       lambda h: h.__setitem__(slice(257, 265), b"ustar  \0"))


@case("RELEASE_MALFORMED", "manifest.json's header checksum is wrong.")
def malformed_bad_checksum(rng):
    data = signed(*make(rng))
    return data[:100] + b"0000755" + data[107:]


@case("RELEASE_MALFORMED", "The file ends inside the payload.")
def malformed_truncated(rng):
    data = signed(*make(rng))
    return data[:len(data) - len(container.END) - 2048]


@case("RELEASE_MALFORMED", "No end-of-archive marker.")
def malformed_no_end_marker(rng):
    return signed(*make(rng))[:-len(container.END)]


@case("RELEASE_MALFORMED", "Non-zero data after the end-of-archive marker.")
def malformed_data_after_end(rng):
    return signed(*make(rng)) + b"\x01" + bytes(511)


# --- 2 SIGNATURE_MALFORMED ------------------------------------------------------------------------

def with_signature_bytes(rng, signature_bytes):
    manifest, entries = make(rng)
    return builder.pack(dumps(manifest), signature_bytes, entries)


@case("SIGNATURE_MALFORMED", "manifest.sig isn't JSON.")
def signature_not_json(rng):
    return with_signature_bytes(rng, b"not json\n")


@case("SIGNATURE_MALFORMED", "manifest.sig has the wrong format.")
def signature_wrong_format(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(manifest_bytes, [("vec-release", test_key("vec-release"))])
    doc["format"] = "other"
    return builder.pack(manifest_bytes, dumps(doc), entries)


@case("SIGNATURE_MALFORMED", "A signature is 63 bytes.")
def signature_short(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(manifest_bytes, [("vec-release", test_key("vec-release"))])
    doc["signatures"][0]["sig"] = doc["signatures"][0]["sig"][:126]
    return builder.pack(manifest_bytes, dumps(doc), entries)


@case("SIGNATURE_MALFORMED", "No signatures.")
def signature_empty(rng):
    return with_signature_bytes(
        rng, dumps({"format": "pelco-release-signature", "format_version": 1, "signatures": []}))


@case("SIGNATURE_MALFORMED", "manifest.sig has a member name twice.")
def signature_duplicate_member(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    valid = sig(manifest_bytes)
    duplicated = valid.replace(b'"format_version": 1,', b'"format_version": 1,\n  "format_version": 1,', 1)
    return builder.pack(manifest_bytes, duplicated, entries)


# --- 3 KEY_UNKNOWN, 4 SIGNATURE_INVALID -----------------------------------------------------------

@case("KEY_UNKNOWN", "Signed only by a key the keyring doesn't know.")
def key_unknown(rng):
    return signed(*make(rng), signers=(UNKNOWN_SIGNER,))


@case("SIGNATURE_INVALID", "The version was changed after signing.")
def signature_manifest_changed(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    changed = manifest_bytes.replace(b'"version": "2.0.0"', b'"version": "9.0.0"', 1)
    return builder.pack(changed, sig(manifest_bytes), entries)


@case("SIGNATURE_INVALID", "A space was added after signing: the manifest is never canonicalised.")
def signature_whitespace_changed(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    return builder.pack(manifest_bytes + b" ", sig(manifest_bytes), entries)


@case("SIGNATURE_INVALID", "Signed by an unknown key but labelled with a known key's ID.")
def signature_wrong_key(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(manifest_bytes, [("vec-release", test_key(UNKNOWN_SIGNER))])
    return builder.pack(manifest_bytes, dumps(doc), entries)


# --- 5 FORMAT_UNSUPPORTED -------------------------------------------------------------------------

@case("FORMAT_UNSUPPORTED", "format_version 2.")
def format_version_2(rng):
    return signed(*make(rng, fields={"format_version": 2}))


@case("FORMAT_UNSUPPORTED", "format_version is the string \"1\".")
def format_version_string(rng):
    return signed(*make(rng, fields={"format_version": "1"}))


@case("FORMAT_UNSUPPORTED", "format_version is written 1.0, which isn't the integer 1.")
def format_version_fraction(rng):
    return with_manifest_bytes(rng, lambda b: b.replace(b'"format_version": 1,', b'"format_version": 1.0,', 1))


@case("FORMAT_UNSUPPORTED", "format isn't \"pelco-release\".")
def format_other(rng):
    return signed(*make(rng, fields={"format": "other-release"}))


# --- 6 MANIFEST_INVALID ---------------------------------------------------------------------------

def with_manifest_bytes(rng, change):
    manifest, entries = make(rng)
    manifest_bytes = change(dumps(manifest))
    return builder.pack(manifest_bytes, sig(manifest_bytes), entries)


@case("MANIFEST_INVALID", "manifest.json isn't JSON.")
def manifest_not_json(rng):
    return with_manifest_bytes(rng, lambda b: b[:-3])


@case("MANIFEST_INVALID", "manifest.json is a JSON array.")
def manifest_not_object(rng):
    return with_manifest_bytes(rng, lambda b: b"[" + b.rstrip() + b"]\n")


@case("MANIFEST_INVALID", "manifest.json starts with a UTF-8 byte order mark.")
def manifest_bom(rng):
    return with_manifest_bytes(rng, lambda b: b"\xef\xbb\xbf" + b)


@case("MANIFEST_INVALID", "manifest.json isn't valid UTF-8.")
def manifest_bad_utf8(rng):
    return with_manifest_bytes(rng, lambda b: b.replace(b"V2.0.0 example", b"V2.0.0 \xff", 1))


@case("MANIFEST_INVALID", "\"version\" appears twice; readers must not pick one.")
def manifest_duplicate_member(rng):
    return with_manifest_bytes(rng, lambda b: b.replace(
        b'  "version": "2.0.0",\n', b'  "version": "2.0.0",\n  "version": "9.0.0",\n', 1))


@case("MANIFEST_INVALID", "A release-channel version with a pre-release part.")
def manifest_release_prerelease(rng):
    return signed(*make(rng, fields={"version": "2.0.0-rc.1"}))


@case("MANIFEST_INVALID", "No routes.")
def manifest_missing_routes(rng):
    manifest, entries = make(rng)
    del manifest["routes"]
    return signed(manifest, entries)


@case("MANIFEST_INVALID", "A hardware ID ends with a newline: a pattern matches the whole string.")
def manifest_newline_in_id(rng):
    return signed(*make(rng, fields={"hardware": ["example-hw-a\n"]}))


@case("MANIFEST_INVALID", "The component doesn't start with the product.")
def manifest_component_not_product(rng):
    return signed(*make(rng, fields={"component": "other.unit.app"}))


@case("MANIFEST_INVALID", "Two payloads with the same name.")
def manifest_duplicate_payload_name(rng):
    return signed(*make(rng, payloads=[payload(rng), payload(rng)]))


@case("MANIFEST_INVALID", "Two encrypted payloads with the same nonce prefix.")
def manifest_duplicate_nonce_prefix(rng):
    manifest, entries = make(rng, payloads=[payload(rng), payload(rng, name="data.bin")])
    manifest["payload"][1]["encryption"]["nonce_prefix"] = manifest["payload"][0]["encryption"]["nonce_prefix"]
    return signed(manifest, entries)


@case("MANIFEST_INVALID", "An encrypted payload's size doesn't match its plain_size and chunk_size.")
def manifest_encrypted_size_wrong(rng):
    manifest, entries = make(rng)
    manifest["payload"][0]["plain_size"] += 1
    return signed(manifest, entries)


@case("MANIFEST_INVALID", "Two recipients with the same key ID.")
def manifest_duplicate_recipient(rng):
    return signed(*make(rng, recipients=["vec-device", "vec-device"]))


@case("MANIFEST_INVALID", "An encrypted payload and no recipients.")
def manifest_no_recipients(rng):
    manifest, entries = make(rng)
    del manifest["recipients"]
    return signed(manifest, entries)


@case("MANIFEST_INVALID", "chunk_size is written 1024.0, which isn't an integer.")
def manifest_integer_fraction(rng):
    return with_manifest_bytes(rng, lambda b: b.replace(b'"chunk_size": 1024', b'"chunk_size": 1024.0', 1))


@case("MANIFEST_INVALID", "A payload size above the 8 GiB a ustar entry can hold.")
def manifest_size_too_large(rng):
    manifest, entries = make(rng, payloads=[payload(rng, encrypt=False)])
    manifest["payload"][0]["size"] = 8589934592
    return signed(manifest, entries)


@case("MANIFEST_INVALID", "An unknown field holds an unpaired surrogate escape.")
def manifest_lone_surrogate(rng):
    return with_manifest_bytes(rng, lambda b: add_member(b, rb'"future_field": "\ud800"'))


@case("MANIFEST_INVALID", "Nested 33 deep in an unknown field.")
def manifest_too_deep(rng):
    return with_manifest_bytes(rng, lambda b: at_limits(b, extra_depth=1))


@case("MANIFEST_INVALID", "4 097 values.")
def manifest_too_many_values(rng):
    return with_manifest_bytes(rng, lambda b: at_limits(b, extra_values=1))


# --- 7 KEY_NOT_PERMITTED --------------------------------------------------------------------------

@case("KEY_NOT_PERMITTED", "A test-only key signed a release-channel release.")
def key_wrong_channel(rng):
    return signed(*make(rng), signers=("vec-test",))


@case("KEY_NOT_PERMITTED", "The key may only sign another product.")
def key_wrong_product(rng):
    return signed(*make(rng), signers=("vec-other-product",))


@case("KEY_NOT_PERMITTED", "The key's not_after is a millisecond before build.built_at.")
def key_expired(rng):
    return signed(*make(rng), signers=("vec-expired",))


@case("KEY_NOT_PERMITTED", "The permitted key's signature doesn't verify; the verifying one isn't permitted.")
def key_permitted_signature_invalid(rng):
    manifest, entries = make(rng)
    manifest_bytes = dumps(manifest)
    doc = builder.signature_file(b"other bytes", [("vec-release", test_key("vec-release"))])
    doc = builder.signature_file(manifest_bytes, [("vec-test", test_key("vec-test"))], doc)
    return builder.pack(manifest_bytes, dumps(doc), entries)


# --- 8 to 15: the target --------------------------------------------------------------------------

@case("CHANNEL_NOT_ALLOWED", "Test release, installer not configured for testing.")
def channel_test_not_accepted(rng):
    return signed(*make(rng, fields={"channel": "test", "version": "2.0.0-rc.1"}),
                  signers=("vec-test",))


@case("WRONG_COMPONENT", "The installer is updating example.unit.boot.", component="example.unit.boot")
def wrong_component(rng):
    return signed(*make(rng))


@case("HARDWARE_INCOMPATIBLE", "The unit's hardware ID isn't listed.", hardware="example-hw-b")
def hardware_incompatible(rng):
    return signed(*make(rng))


@case("ROUTE_NOT_ALLOWED", "Installing over ble, which the release doesn't list.", route="ble")
def route_not_allowed(rng):
    return signed(*make(rng))


@case("REQUIREMENT_NOT_MET", "Unit requirement below min.",
      installed=installed(unit={"example.unit.boot": "0.9.0"}))
def requirement_below_min(rng):
    return signed(*make(rng))


@case("REQUIREMENT_NOT_MET", "Unit requirement at 1.0.0-rc.1, which is below min 1.0.0.",
      installed=installed(unit={"example.unit.boot": "1.0.0-rc.1"}))
def requirement_prerelease_below_min(rng):
    return signed(*make(rng))


@case("REQUIREMENT_NOT_MET", "System requirement at max_exclusive.",
      installed=installed(system={"example.parent.app": "4.0.0"}))
def requirement_at_max(rng):
    return signed(*make(rng))


@case("REQUIREMENT_NOT_MET", "System requirement's version unknown.",
      installed={"unit": {"example.unit.app": "1.5.0", "example.unit.boot": "1.2.0"}, "system": {}})
def requirement_unknown(rng):
    return signed(*make(rng))


@case("REQUIREMENT_NOT_MET", "The unit requirement is installed elsewhere in the system, not on the unit.",
      installed={"unit": {"example.unit.app": "1.5.0"},
                 "system": {"example.parent.app": "3.1.0", "example.unit.boot": "1.2.0"}})
def requirement_wrong_scope(rng):
    return signed(*make(rng))


@case("ALREADY_INSTALLED", "Same version installed.", installed=installed(unit={"example.unit.app": "2.0.0"}))
def already_installed(rng):
    return signed(*make(rng))


@case("DOWNGRADE_NOT_ALLOWED", "Newer version installed.",
      installed=installed(unit={"example.unit.app": "2.1.0"}))
def downgrade(rng):
    return signed(*make(rng))


@case("DOWNGRADE_NOT_ALLOWED", "10.0.0 installed is newer than 2.0.0: versions compare numerically.",
      installed=installed(unit={"example.unit.app": "10.0.0"}))
def downgrade_numeric(rng):
    return signed(*make(rng))


@case("PAYLOAD_TYPE_UNSUPPORTED", "A payload type the installer doesn't know.")
def payload_type_unsupported(rng):
    return signed(*make(rng, payloads=[payload(rng, type_="future-type")]))


# --- 16 NO_RECIPIENT_KEY, 17 KEY_UNWRAP_FAILED ----------------------------------------------------

@case("NO_RECIPIENT_KEY", "The installer holds no key the release lists.",
      recipient_keys=[UNLISTED_RECIPIENT])
def no_recipient_key(rng):
    return signed(*make(rng))


@case("KEY_UNWRAP_FAILED", "The wrapped key was changed before signing.")
def unwrap_tampered(rng):
    manifest, entries = make(rng)
    r = manifest["recipients"][0]
    r["wrapped_key"] = flip(bytes.fromhex(r["wrapped_key"]), 8).hex()
    return signed(manifest, entries)


@case("KEY_UNWRAP_FAILED", "The vec-device entry holds the key wrapped for vec-host.")
def unwrap_wrong_recipient(rng):
    manifest, entries = make(rng)
    device, host = manifest["recipients"]
    device.update(ephemeral_pub=host["ephemeral_pub"], wrapped_key=host["wrapped_key"])
    return signed(manifest, entries)


@case("KEY_UNWRAP_FAILED", "ephemeral_pub is all zeros, giving an all-zero shared secret.")
def unwrap_zero_point(rng):
    manifest, entries = make(rng)
    manifest["recipients"][0]["ephemeral_pub"] = "00" * 32
    return signed(manifest, entries)


# --- 18 to 21: payloads ---------------------------------------------------------------------------

@case("PAYLOAD_SIZE_MISMATCH", "The payload entry is a byte longer than the manifest says.")
def size_longer(rng):
    manifest, entries = make(rng, payloads=[payload(rng, encrypt=False)])
    return signed(manifest, [("app.bin", entries[0][1] + b"\0")])


@case("PAYLOAD_SIZE_MISMATCH", "The payload entry is a byte shorter than the manifest says.")
def size_shorter(rng):
    manifest, entries = make(rng, payloads=[payload(rng, encrypt=False)])
    return signed(manifest, [("app.bin", entries[0][1][:-1])])


@case("PAYLOAD_HASH_MISMATCH", "One byte of an unencrypted payload changed.")
def hash_mismatch(rng):
    manifest, entries = make(rng, payloads=[payload(rng, encrypt=False)])
    return signed(manifest, [("app.bin", flip(entries[0][1], 2500))])


@case("DECRYPT_FAILED", "One byte of chunk 1 changed, with sha256 updated to match.")
def decrypt_chunk_changed(rng):
    manifest, entries = make(rng)
    stored = flip(entries[0][1], 1040 + 10)
    rehash(manifest, 0, stored)
    return signed(manifest, [("app.bin", stored)])


@case("DECRYPT_FAILED", "Chunks 0 and 1 swapped, with sha256 updated to match.")
def decrypt_chunks_swapped(rng):
    manifest, entries = make(rng)
    stored = entries[0][1]
    stored = stored[1040:2080] + stored[:1040] + stored[2080:]
    rehash(manifest, 0, stored)
    return signed(manifest, [("app.bin", stored)])


@case("DECRYPT_FAILED", "The last chunk removed, with sizes and hashes updated: the new last chunk isn't marked last.")
def decrypt_truncated(rng):
    plain = payload(rng, size=5000)
    manifest, entries = make(rng, payloads=[plain])
    stored = entries[0][1][:4 * 1040]
    p = manifest["payload"][0]
    p.update(size=len(stored), plain_size=4096,
             plain_sha256=hashlib.sha256(plain["data"][:4096]).hexdigest())
    rehash(manifest, 0, stored)
    return signed(manifest, [("app.bin", stored)])


@case("DECRYPT_FAILED", "The recipients unwrap a different release's content key.")
def decrypt_wrong_content_key(rng):
    manifest, entries = make(rng)
    other, _ = make(rng)
    manifest["recipients"] = other["recipients"]
    return signed(manifest, entries)


@case("PLAIN_HASH_MISMATCH", "plain_sha256 doesn't match the decrypted image.")
def plain_hash_mismatch(rng):
    manifest, entries = make(rng)
    p = manifest["payload"][0]
    p["plain_sha256"] = flip(bytes.fromhex(p["plain_sha256"]), 0).hex()
    return signed(manifest, entries)


# --- output ---------------------------------------------------------------------------------------

def keyring():
    return {"format": "pelco-release-keyring", "format_version": 1, "keys": [
        {"key_id": k, "alg": "ed25519", "public_key": crypto.ed25519_public(test_key(k)).hex(), **rules}
        for k, rules in SIGNING_KEYS.items()]}


def test_keys():
    signing = [*SIGNING_KEYS, UNKNOWN_SIGNER]
    recipients = [*RECIPIENTS, UNLISTED_RECIPIENT]
    return {
        "description": "TEST KEYS ONLY. Published so anyone can rebuild the vectors; never trust them in a product.",
        "keys": [{"key_id": k, "alg": "ed25519", "private_key": test_key(k).hex(),
                  "public_key": crypto.ed25519_public(test_key(k)).hex()} for k in signing]
        + [{"key_id": k, "alg": "x25519", "private_key": test_key(k).hex(),
            "public_key": crypto.x25519_public(test_key(k)).hex()} for k in recipients]}


def generate():
    files = {"keyring.json": dumps(keyring()), "test-keys.json": dumps(test_keys())}
    index = []
    for c in CASES:
        name = f"{c['name']}.prel"
        files[name] = c["make"](Seeded(c["name"]))
        index.append({"name": c["name"], "file": name, "expected": c["expected"],
                      "description": c["description"], "context": {**CONTEXT, **c["context"]}})
    files["vectors.json"] = dumps({
        "format": "pelco-release-vectors", "format_version": 1,
        "keyring": "keyring.json", "test_keys": "test-keys.json", "cases": index})
    return files


def run(files):
    """Every case's result from the reference checker, as failure messages."""
    keys = {k["key_id"]: bytes.fromhex(k["private_key"])
            for k in json.loads(files["test-keys.json"])["keys"] if k["alg"] == "x25519"}
    ring = verifier.load_keyring(json.loads(files["keyring.json"]))
    failures = []
    cases = json.loads(files["vectors.json"])["cases"]
    for c in cases:
        ctx = verifier.Context.from_json(c["context"], {k: keys[k] for k in c["context"]["recipient_keys"]})
        result = verifier.check(io.BytesIO(files[c["file"]]), ring, ctx)
        if result.code != c["expected"]:
            failures.append(f"{c['name']}: expected {c['expected']}, got {result.code} {result.detail}")
    missing = set(NUMBERS) - {c["expected"] for c in cases}
    if missing:
        failures.append(f"no case for {', '.join(sorted(missing))}")
    return failures, len(cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = generate()
    failures, count = run(files)
    if args.check:
        on_disk = {p.name for p in OUT.iterdir() if p.name != "README.md"}
        for name in sorted(on_disk - set(files)):
            failures.append(f"{name}: not produced by the generator")
        for name, data in files.items():
            path = OUT / name
            if not path.exists() or path.read_bytes() != data:
                failures.append(f"{name}: differs from the generator's output")
    else:
        OUT.mkdir(exist_ok=True)
        for p in OUT.glob("*.prel"):
            if p.name not in files:
                p.unlink()
        for name, data in files.items():
            (OUT / name).write_bytes(data)
    if failures:
        print("\n".join(failures))
        sys.exit(1)
    print(f"vectors OK: {count} cases, every result code covered")


if __name__ == "__main__":
    main()
