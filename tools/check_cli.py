#!/usr/bin/env python3
"""Runs the command line end to end: keygen, build, sign, pack and verify, in a temporary directory."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cli(*args, cwd, env=None, expect=0):
    result = subprocess.run([sys.executable, "-m", "pelco_release", *args], cwd=cwd,
                            env={**os.environ, "PYTHONPATH": str(ROOT), **(env or {})},
                            capture_output=True, text=True)
    if result.returncode != expect:
        sys.exit(f"pelco-release {' '.join(args)}: exit {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    signer = json.loads(cli("keygen", "signing", "demo-test", "--out", "signing.key",
                            "--channel", "test", "--product", "demo", cwd=d))
    device = json.loads(cli("keygen", "recipient", "demo-device", "--out", "device.key", cwd=d))
    cli("keygen", "recipient", "demo-device", "--out", "device.key", cwd=d, expect=1)
    (d / "app.bin").write_bytes(os.urandom(3000))
    (d / "boot.bin").write_bytes(os.urandom(1500))
    (d / "spec.json").write_text(json.dumps({
        "manifest": {
            "format": "pelco-release", "format_version": 1, "product": "demo",
            "component": "demo.unit.app", "version": "1.0.0-rc.1", "reported_version": "1.0.0-rc.1",
            "channel": "test", "hardware": ["demo-hw"], "routes": ["usb"],
            "build": {"source": "demo@v1.0.0-rc.1", "commit": "0" * 40}},
        "payload": [{"name": "app.bin", "type": "raw-bin", "file": "app.bin", "encrypt": True},
                    {"name": "boot.bin", "type": "raw-bin", "file": "boot.bin"}],
        "recipients": [device]}))
    (d / "keyring.json").write_text(json.dumps(
        {"format": "pelco-release-keyring", "format_version": 1, "keys": [signer]}))
    (d / "context.json").write_text(json.dumps({
        "checks": "installer", "accept_test": True, "component": "demo.unit.app",
        "hardware": "demo-hw", "route": "usb", "payload_types": ["raw-bin"]}))

    cli("build", "spec.json", "--out", "release", cwd=d)
    cli("sign", "release", "--key-env", "SIGNING_KEY", cwd=d,
        env={"SIGNING_KEY": (d / "signing.key").read_text()})
    cli("pack", "release", "--out", "demo.prel", cwd=d)
    cli("verify", "demo.prel", "--keyring", "keyring.json", cwd=d)
    cli("verify", "demo.prel", "--keyring", "keyring.json", "--context", "context.json",
        "--recipient-key", "device.key", cwd=d)
    out = cli("verify", "demo.prel", "--keyring", "keyring.json", "--context", "context.json",
              cwd=d, expect=1)
    if not out.startswith("NO_RECIPIENT_KEY"):
        sys.exit(f"expected NO_RECIPIENT_KEY, got {out}")

print("cli OK")
