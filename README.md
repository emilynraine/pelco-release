# pelco-release

The firmware release format shared by every Pelco product, and the code and tests that keep every
implementation of it in agreement.

A release is one component at one version: a signed, optionally encrypted file that can travel from
a build, through PelcoHub and PelcoOne or a controller, to the unit it installs on, over Bluetooth,
USB, serial, a network or a parent device. Every party that handles it checks it the same way and
reports failures with the same result codes.

## What lives here, and what doesn't

This repository is **product-free**. It owns the format, never the products.

| Here | Not here |
| --- | --- |
| The format spec and JSON Schemas | Component IDs, hardware IDs, routes per product: those are each product's definition |
| Generic vocabulary: routes, payload types, result codes | How a product transfers or writes an image (Bluetooth protocols, bootloader commands, RAUC) |
| Test cases every implementation must pass | Choosing what to install, running update jobs, UI |
| The release builder and Python reference reader | The Kotlin reader, which lives in pelco-kmp with the Device Library |
| The C reader, for devices and controllers | Private keys of any kind, other than the published test keys |
| The reusable CI signing workflow | Each product's build of its firmware |

A product's update code calls the reader with what only it knows: the target component, the unit's
hardware ID, the installed versions and the route in use. The reader checks the release and streams
the decrypted image into a writer the product supplies.

## Layout

```
spec/
  release-format.md      the normative format: container, manifest, encryption, signature, check order
  schema/                JSON Schemas: manifest, manifest.sig, keyring
  registry/              routes and payload types
  result-codes.json      result codes every implementation reports
examples/                example manifests, signature and keyring (placeholder hashes and keys)
pelco_release/           reference implementation and command line: build, sign, pack, verify
c/                       the C reader library and its conformance runner (see c/README.md)
vectors/                 conformance cases: release files, contexts and expected result codes
tools/
  check_spec.py          checks the schemas, examples and registries
  check_cli.py           runs the command line end to end
  make_vectors.py        generates vectors/, or checks it with --check
  differential.py        checks another reader agrees with the reference on mutated releases
.github/workflows/
  ci.yml                 every check below, on every push
  sign-release.yml       reusable workflow that builds, signs and packs a product's release
```

## Building a release

```bash
python -m pip install -r requirements.txt

python -m pelco_release keygen signing duo-test-2026 --out duo-test.key --channel test --product duo
python -m pelco_release keygen recipient duo-controller-2026 --out duo-controller.key
python -m pelco_release build release.json --out build/release
python -m pelco_release sign build/release --key duo-test.key   # or --key-env, for CI secrets
python -m pelco_release pack build/release --out duo.button.app-2.3.0.prel
python -m pelco_release verify duo.button.app-2.3.0.prel --keyring keyring.json
```

`keygen` prints the public half: a keyring entry for a signing key, or a `key_id` and
`public_key` for a recipient key. Keep `.key` files out of git; `.gitignore` already excludes them.

`build` takes a build spec: every manifest field except `payload` and `recipients`, the payload
files, and the recipients' public keys. `build.built_at` is filled in if absent.

```json
{
  "manifest": {
    "format": "pelco-release", "format_version": 1,
    "product": "duo", "component": "duo.button.app",
    "version": "2.3.0", "reported_version": "2.3.0", "channel": "release",
    "hardware": ["duo-button-v1"], "routes": ["relay", "usb", "ble"],
    "build": { "source": "guardian-duo@v2.3.0", "commit": "5afb83f7c5637d0e396f3aa99ed141dd4afd40b9" }
  },
  "payload": [
    { "name": "duo.bin", "type": "raw-bin", "file": "out/duo.bin", "encrypt": true, "chunk_size": 4096 }
  ],
  "recipients": [
    { "key_id": "duo-controller-2026", "public_key": "…64 hex characters…" }
  ]
}
```

`verify` without `--context` runs the verifier's checks (steps 1–5). With a context file, in the
form described in `vectors/README.md`, and `--recipient-key` for each key held, it runs as an
installer. It exits 0 only for `OK`.

## Signing in CI

A product's workflow builds its firmware, uploads the payload files and a build spec as an artifact,
then calls `sign-release.yml`, which builds, signs and packs the release and uploads the `.prel` file:

```yaml
jobs:
  firmware:
    runs-on: ubuntu-latest
    steps:
      # ... build out/duo.bin, write release.json naming it ...
      - uses: actions/upload-artifact@v4
        with:
          name: duo-button-app
          path: |
            release.json
            out/duo.bin

  release:
    needs: firmware
    uses: emilynraine/pelco-release/.github/workflows/sign-release.yml@v0.1.0
    with:
      artifact: duo-button-app
      spec: release.json
      environment: firmware-test
      pelco-release-ref: v0.1.0
```

The signing key is the private key file's contents, stored as the secret `PELCO_RELEASE_SIGNING_KEY`
in a GitHub environment of the product's repository: one environment per signing key, for example
`firmware-test` for the test key and `firmware-release` for the release key. Give the release
environment required reviewers and restrict it to protected branches or tags, so a release-channel
signature always needs a person's approval. Nothing outside that environment ever sees the key.

## Checking

```bash
python tools/check_spec.py
python tools/check_cli.py
python tools/make_vectors.py --check

cmake -S c -B c/build && cmake --build c/build && ctest --test-dir c/build
python tools/differential.py --runner c/build/run_vectors
```

CI runs all of these on every push, and the C checks again under AddressSanitizer and UBSan.

## Versioning

- The repository is tagged with semver. Consumers pin a tag.
- The manifest's `format_version` is separate: it changes only when a reader must understand
  something new to install safely. A library fix is a new tag, not a new format version.
- Result codes and registry IDs are never renumbered, renamed or reused.

## Changing the format

A change lands here first, as a spec change plus test cases. Each implementation then updates its
pinned tag and passes the new cases.
