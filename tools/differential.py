#!/usr/bin/env python3
"""Checks that a reader agrees with the reference on releases nobody wrote a vector for.

Mutates manifests at random (values of the wrong type or shape, missing and extra fields, odd strings,
stray bytes), signs them so the mutation reaches the later steps, takes the reference reader's result
as expected, and runs another reader's conformance runner over the lot.

    python tools/differential.py --runner c/build/run_vectors [--count 2000] [--seed 1] [--out DIR]
"""
import argparse
import copy
import io
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_vectors as mv  # noqa: E402
from pelco_release import builder, verifier  # noqa: E402
from pelco_release.manifest import dumps  # noqa: E402

VALUES = [
    0, 1, -1, 2, 1.0, 1e3, 1024, 1048577, 8589934591, 8589934592, 2 ** 64, True, False, None,
    "", "x", "example", "example.unit.app", "example.unit", "Example", "a" * 33, "a" * 65, "-x", "x-",
    "x.y", "x..y", "1.0.0", "2.0.0", "2.0.0-rc.1", "2.0.0-01", "01.0.0", "1.0", "1.0.0+b", "test",
    "release", "unit", "system", "raw-bin", "future-type", "ab" * 8, "ab" * 32, "AB" * 32, "ab" * 40,
    "2026-10-19T15:24:00Z", "2026-10-19T15:24:00.5Z", "2026-10-19T15:24:00.Z", "2026-10-19 15:24:00Z",
    "manifest.json", "manifest.sig", "app.bin", "caf\u00e9", "tab\there", "line\n", " ", "~", [], {},
    ["x"], ["example-hw-a", "example-hw-a"], [1], {"a": 1},
]
MEMBER_NAMES = ["format", "format_version", "product", "component", "version", "reported_version",
                "channel", "hardware", "requires", "routes", "payload", "recipients", "build", "name",
                "type", "size", "sha256", "encryption", "plain_size", "plain_sha256", "alg",
                "chunk_size", "nonce_prefix", "key_id", "ephemeral_pub", "wrapped_key", "scope", "min",
                "max_exclusive", "source", "commit", "built_at", "future_field"]
CHARS = " \n\t.-_A9z\u00e9\x7f/\"\\"


def locations(doc, found=None):
    """Every (container, key) in the document."""
    found = [] if found is None else found
    items = doc.items() if isinstance(doc, dict) else enumerate(doc) if isinstance(doc, list) else []
    for key, value in items:
        found.append((doc, key))
        locations(value, found)
    return found


def mutate_string(rnd, s):
    i = rnd.randrange(len(s) + 1)
    if s and rnd.random() < 0.5:
        return s[:i] + s[i + 1:]
    return s[:i] + rnd.choice(CHARS) + s[i:]


def mutate(rnd, doc):
    container, key = rnd.choice(locations(doc))
    op = rnd.random()
    if op < 0.45:
        value = container[key]
        container[key] = (mutate_string(rnd, value) if isinstance(value, str) and rnd.random() < 0.5
                          else copy.deepcopy(rnd.choice(VALUES)))
    elif op < 0.65:
        del container[key]
    elif op < 0.85:
        target = container[key] if isinstance(container[key], dict) else container
        if isinstance(target, dict):
            target[rnd.choice(MEMBER_NAMES)] = copy.deepcopy(rnd.choice(VALUES))
        else:
            target.append(copy.deepcopy(rnd.choice(VALUES)))
    elif isinstance(container, list):
        container.append(copy.deepcopy(container[key]))
    else:
        container[key] = [copy.deepcopy(container[key])]


def mutate_bytes(rnd, data):
    i = rnd.randrange(len(data))
    op = rnd.random()
    if op < 0.4:
        return data[:i] + data[i + 1:]
    byte = bytes([rnd.choice(b' \n,:{}[]"\\0a-.\x00\xff\xc3')])
    return data[:i] + byte + data[i + (op >= 0.7):]


def release(rnd, rng):
    shape = rnd.random()
    payloads = ([mv.payload(rng, encrypt=False)] if shape < 0.3
                else [mv.payload(rng), mv.payload(rng, size=700, name="data.bin")] if shape < 0.45
                else None)
    manifest, entries = mv.make(rng, payloads=payloads)
    for _ in range(rnd.choice([1, 1, 1, 2, 3])):
        if manifest:
            mutate(rnd, manifest)
    manifest_bytes = dumps(manifest)
    if rnd.random() < 0.15:
        manifest_bytes = mutate_bytes(rnd, manifest_bytes)
    signer = rnd.choice(["vec-release"] * 6 + ["vec-test", "vec-until-build", "vec-expired"])
    signature = builder.signature_file(manifest_bytes, [(signer, mv.test_key(signer))])
    if rnd.random() < 0.05:
        mutate(rnd, signature)
    return builder.pack(manifest_bytes, dumps(signature), entries)


def context(rnd):
    ctx = copy.deepcopy(mv.CONTEXT)
    ctx["accept_test"] = rnd.random() < 0.3
    ctx["checks"] = rnd.choice(["installer"] * 8 + ["host", "verifier"])
    if rnd.random() < 0.1:
        ctx["installed"]["unit"]["example.unit.app"] = rnd.choice(["2.0.0", "2.0.0-rc.1", "3.0.0", "0.0.1"])
    return ctx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", help="a conformance runner taking a vectors directory")
    parser.add_argument("--out", help="keep the releases in this directory")
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    rnd = random.Random(args.seed)
    files = mv.generate()
    keys = {k["key_id"]: bytes.fromhex(k["private_key"])
            for k in json.loads(files["test-keys.json"])["keys"] if k["alg"] == "x25519"}
    ring = verifier.load_keyring(json.loads(files["keyring.json"]))
    tally = {}
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(args.out or tmp)
        out.mkdir(parents=True, exist_ok=True)
        cases = []
        for i in range(args.count):
            data = release(rnd, mv.Seeded(f"differential {args.seed} {i}"))
            ctx = context(rnd)
            keys_held = {k: keys[k] for k in ctx["recipient_keys"]}
            result = verifier.check(io.BytesIO(data), ring, verifier.Context.from_json(ctx, keys_held))
            tally[result.code] = tally.get(result.code, 0) + 1
            name = f"case-{i}"
            (out / f"{name}.prel").write_bytes(data)
            cases.append({"name": name, "file": f"{name}.prel", "expected": result.code,
                          "description": result.detail, "context": ctx})
        (out / "keyring.json").write_bytes(files["keyring.json"])
        (out / "test-keys.json").write_bytes(files["test-keys.json"])
        (out / "vectors.json").write_bytes(dumps({"format": "pelco-release-vectors", "format_version": 1,
                                                 "keyring": "keyring.json", "test_keys": "test-keys.json",
                                                 "cases": cases}))
        if not args.runner:
            print(f"wrote {args.count} releases to {out}")
            return
        run = subprocess.run([args.runner, str(out)], capture_output=True, text=True)
        if run.returncode != 0:
            print(run.stdout[-6000:], run.stderr[-2000:])
            failed = [line.split()[0] for line in run.stdout.splitlines() if line.startswith("case-")]
            for name in list(dict.fromkeys(failed))[:5]:
                manifest = (out / f"{name}.prel").read_bytes()[512:512 + 4096].split(bytes(1))[0]
                print(f"\n{name} manifest:\n{manifest.decode('utf-8', 'replace')}")
            sys.exit(1)
    print(f"differential OK: {args.count} releases agree "
          f"({', '.join(f'{k} {v}' for k, v in sorted(tally.items(), key=lambda kv: -kv[1]))})")


if __name__ == "__main__":
    main()
