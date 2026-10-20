#!/usr/bin/env python3
"""Checks the spec's own files: schemas are valid, examples match them, the schemas
reject what the format forbids, and the registries and result codes are consistent.

Run from the repository root: python tools/check_spec.py
"""
import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec"
EXAMPLES = ROOT / "examples"

failures = []


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validator(name):
    schema = load(SPEC / "schema" / f"{name}.schema.json")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def expect_valid(v, doc, label):
    errors = list(v.iter_errors(doc))
    if errors:
        failures.append(f"{label}: expected valid, got: {errors[0].message}")


def expect_invalid(v, doc, label):
    if v.is_valid(doc):
        failures.append(f"{label}: expected the schema to reject it")


def mutated(doc, change):
    copy_ = copy.deepcopy(doc)
    change(copy_)
    return copy_


manifest = validator("manifest")
signature = validator("signature")
keyring = validator("keyring")

for path in sorted(EXAMPLES.glob("*.manifest.json")):
    expect_valid(manifest, load(path), path.name)
expect_valid(signature, load(EXAMPLES / "manifest.sig.json"), "manifest.sig.json")
expect_valid(keyring, load(EXAMPLES / "keyring.json"), "keyring.json")

encrypted = load(EXAMPLES / "duo-button-app.manifest.json")
plain = load(EXAMPLES / "duo-controller-os.manifest.json")

rejections = {
    "release channel with a pre-release version":
        mutated(encrypted, lambda m: m.update(version="2.3.0-rc.1")),
    "version with build metadata":
        mutated(encrypted, lambda m: m.update(version="2.3.0+build.5")),
    "encrypted payload without recipients":
        mutated(encrypted, lambda m: m.pop("recipients")),
    "encrypted payload without plain_sha256":
        mutated(encrypted, lambda m: m["payload"][0].pop("plain_sha256")),
    "plain payload with plain_size":
        mutated(plain, lambda m: m["payload"][0].update(plain_size=1)),
    "payload named manifest.json":
        mutated(plain, lambda m: m["payload"][0].update(name="manifest.json")),
    "requirement with neither min nor max_exclusive":
        mutated(plain, lambda m: [m["requires"][0].pop(k) for k in ("min", "max_exclusive")]),
    "requirement without scope":
        mutated(plain, lambda m: m["requires"][0].pop("scope")),
    "component with two parts":
        mutated(plain, lambda m: m.update(component="duo.os")),
    "empty hardware list":
        mutated(plain, lambda m: m.update(hardware=[])),
    "duplicate route":
        mutated(plain, lambda m: m.update(routes=["network", "network"])),
    "uppercase hash":
        mutated(plain, lambda m: m["payload"][0].update(sha256=m["payload"][0]["sha256"].upper())),
    "chunk size below minimum":
        mutated(encrypted, lambda m: m["payload"][0]["encryption"].update(chunk_size=512)),
    "unknown format version":
        mutated(plain, lambda m: m.update(format_version=2)),
    "build time without UTC":
        mutated(plain, lambda m: m["build"].update(built_at="2026-10-19T15:24:00+02:00")),
}
for label, doc in rejections.items():
    expect_invalid(manifest, doc, label)

# Unknown fields are ignored, at the top level and inside objects.
expect_valid(manifest, mutated(plain, lambda m: m.update(future_field=True)), "unknown top-level field")
expect_valid(manifest, mutated(plain, lambda m: m["payload"][0].update(future_field=True)), "unknown payload field")

codes = load(SPEC / "result-codes.json")["codes"]
for key in ("code", "number"):
    values = [c[key] for c in codes]
    if len(values) != len(set(values)):
        failures.append(f"result-codes.json: duplicate {key}")

for registry, key in (("routes", "routes"), ("payload-types", "payload_types")):
    ids = [entry["id"] for entry in load(SPEC / "registry" / f"{registry}.json")[key]]
    if len(ids) != len(set(ids)):
        failures.append(f"registry/{registry}.json: duplicate id")

if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"spec OK: {len(list(EXAMPLES.glob('*.json')))} examples, {len(rejections)} rejections, {len(codes)} result codes")
