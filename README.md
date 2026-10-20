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
| The C reader for devices and controllers (planned) | The Kotlin reader, which lives in pelco-kmp with the Device Library |
| The release builder and CI signing workflow (planned) | Private keys of any kind |

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
tools/
  check_spec.py          checks the schemas, examples and registries
```

Planned: `vectors/` (signed and encrypted test releases with expected results), `tools/` release
builder, `ci/` reusable signing workflow, `c/` reader library.

## Checking the spec

```bash
python -m pip install -r tools/requirements.txt
python tools/check_spec.py
```

CI runs the same check on every push.

## Versioning

- The repository is tagged with semver. Consumers pin a tag.
- The manifest's `format_version` is separate: it changes only when a reader must understand
  something new to install safely. A library fix is a new tag, not a new format version.
- Result codes and registry IDs are never renumbered, renamed or reused.

## Changing the format

A change lands here first, as a spec change plus test cases. Each implementation then updates its
pinned tag and passes the new cases.
