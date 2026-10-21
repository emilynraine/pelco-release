"""pelco-release command line: keygen, build, sign, pack, verify."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import builder, crypto, verifier
from .codes import NUMBERS
from .manifest import dumps, parse_json, problems


def _keygen(args):
    out = Path(args.out)
    if out.exists():
        sys.exit(f"{out} already exists")
    private = os.urandom(32)
    if args.kind == "signing":
        if not args.channel or not args.product:
            sys.exit("a signing key needs --channel and --product")
        public = {"key_id": args.key_id, "alg": "ed25519",
                  "public_key": crypto.ed25519_public(private).hex(),
                  "channels": args.channel, "products": args.product}
        alg = "ed25519"
    else:
        public = {"key_id": args.key_id, "public_key": crypto.x25519_public(private).hex()}
        alg = "x25519"
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dumps(builder.private_key_file(args.key_id, alg, private)))
    print(dumps(public).decode(), end="")


def _build(args):
    spec_path = Path(args.spec)
    spec = parse_json(spec_path.read_bytes())
    fields = dict(spec["manifest"])
    fields["build"] = dict(fields["build"])
    fields["build"].setdefault(
        "built_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    payloads = [dict(p, data=(spec_path.parent / p["file"]).read_bytes()) for p in spec["payload"]]
    recipients = [(r["key_id"], bytes.fromhex(r["public_key"])) for r in spec.get("recipients", [])]
    manifest, entries = builder.build(fields, payloads, recipients)
    if found := problems(manifest):
        sys.exit("invalid manifest:\n  " + "\n  ".join(found))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_bytes(dumps(manifest))
    (out / "manifest.sig").unlink(missing_ok=True)
    for name, data in entries:
        (out / name).write_bytes(data)
    print(f"built {manifest['component']} {manifest['version']} in {out}")


def _sign(args):
    directory = Path(args.dir)
    if args.key_env:
        key_bytes = os.environ.get(args.key_env, "").encode()
        if not key_bytes:
            sys.exit(f"{args.key_env} is empty")
    else:
        key_bytes = Path(args.key).read_bytes()
    key_id, private = builder.load_private_key(key_bytes, "ed25519")
    sig_path = directory / "manifest.sig"
    existing = parse_json(sig_path.read_bytes()) if sig_path.exists() else None
    doc = builder.signature_file((directory / "manifest.json").read_bytes(), [(key_id, private)],
                                 existing)
    sig_path.write_bytes(dumps(doc))
    print(f"signed with {key_id}")


def _pack(args):
    directory = Path(args.dir)
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = parse_json(manifest_bytes)
    data = builder.pack(manifest_bytes, (directory / "manifest.sig").read_bytes(),
                        [(p["name"], (directory / p["name"]).read_bytes()) for p in manifest["payload"]])
    out = Path(args.out)
    if out.is_dir():
        out = out / f"{manifest['component']}-{manifest['version']}.prel"
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes)")


def _verify(args):
    keyring = verifier.load_keyring(parse_json(Path(args.keyring).read_bytes()))
    context = parse_json(Path(args.context).read_bytes()) if args.context else {"checks": "verifier"}
    keys = dict(builder.load_private_key(Path(k).read_bytes(), "x25519") for k in args.recipient_key)
    ctx = verifier.Context.from_json(context, keys)
    with open(args.release, "rb") as f:
        result = verifier.check(f, keyring, ctx)
    print(f"{result.code} ({NUMBERS[result.code]})" + (f": {result.detail}" if result.detail else ""))
    if result.manifest:
        print(json.dumps({k: result.manifest[k] for k in ("component", "version", "channel")}))
    return 0 if result.code == "OK" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pelco-release")
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("keygen", help="create a signing or recipient key pair")
    p.add_argument("kind", choices=["signing", "recipient"])
    p.add_argument("key_id")
    p.add_argument("--out", required=True, help="private key file to create; keep it out of git")
    p.add_argument("--channel", action="append", choices=["test", "release"])
    p.add_argument("--product", action="append")
    p.set_defaults(run=_keygen)

    p = commands.add_parser("build", help="build an unsigned release directory from a build spec")
    p.add_argument("spec")
    p.add_argument("--out", required=True)
    p.set_defaults(run=_build)

    p = commands.add_parser("sign", help="add a signature to a release directory")
    p.add_argument("dir")
    key = p.add_mutually_exclusive_group(required=True)
    key.add_argument("--key", help="private key file")
    key.add_argument("--key-env", help="environment variable holding the private key file's contents")
    p.set_defaults(run=_sign)

    p = commands.add_parser("pack", help="pack a signed release directory into a .prel file")
    p.add_argument("dir")
    p.add_argument("--out", required=True, help="file, or directory to write <component>-<version>.prel in")
    p.set_defaults(run=_pack)

    p = commands.add_parser("verify", help="check a .prel file and print its result code")
    p.add_argument("release")
    p.add_argument("--keyring", required=True)
    p.add_argument("--context", help="installer context JSON; without it only steps 1-5 run")
    p.add_argument("--recipient-key", action="append", default=[], help="X25519 private key file")
    p.set_defaults(run=_verify)

    args = parser.parse_args(argv)
    return args.run(args) or 0
