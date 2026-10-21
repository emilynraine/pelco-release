# C reader

Checks a release as it arrives and streams the decrypted payloads into a writer the product
supplies. It's for devices and controllers: C99, no allocation of its own beyond what the crypto
backend needs, and the release can be fed in pieces of any size.

## Using it

```c
#include "pelco_release.h"

static const char *const duo[] = {"duo"};
static const prel_signing_key keyring[] = {
    {"duo-release-2026", {/* 32 bytes */}, PREL_CHANNEL_RELEASE, duo, 1, NULL},
};
static const char *const types[] = {"raw-bin"};

prel_installed unit[] = {{"duo.button.app", "2.2.0"}, {"duo.button.boot", "1.4.0"}};
prel_installed system[] = {{"duo.controller.app", "4.2.0"}};
prel_recipient_key held[] = {{"duo-controller-2026", {/* 32 bytes */}}};

prel_context ctx = {
    .checks = PREL_CHECKS_INSTALLER,
    .keyring = keyring, .keyring_count = 1,
    .component = "duo.button.app", .hardware = "duo-button-v1", .route = "relay",
    .unit = unit, .unit_count = 2, .system = system, .system_count = 1,
    .payload_types = types, .payload_type_count = 1,
    .recipient_keys = held, .recipient_key_count = 1,
};
prel_writer writer = {my_state, my_begin, my_write, my_commit, my_abort};

prel_reader *r = prel_reader_init(malloc(prel_reader_size()), prel_reader_size(), &ctx, &writer);
prel_result res = PREL_PENDING;
while (res == PREL_PENDING && (n = receive(buf, sizeof buf)) > 0)
    res = prel_reader_feed(r, buf, n);
if (res == PREL_PENDING) res = prel_reader_finish(r);
log("%s: %s", prel_result_name(res), prel_reader_detail(r));
prel_reader_release(r);
```

The writer gets `begin` for each payload, its decrypted bytes through `write`, then `commit` only if
every check passed for every payload, or `abort` on any failure. Bytes written before `commit` aren't
trusted yet: write them to an inactive slot, and make it bootable only in `commit` (spec section 7.1).

A host checking before it sends a release on uses `PREL_CHECKS_HOST` (steps 1 to 12, no keys or
writer needed); a verifier such as PelcoHub uses `PREL_CHECKS_VERIFIER` (steps 1 to 5). Either
returns its result as soon as the manifest is checked, without reading the payloads.

Versions in `unit` and `system` are semver, mapped from whatever the unit reports by the product's
own code. A missing or unparseable version is unknown: it fails a requirement but passes the
version check, so a unit that can't report a version can still be recovered.

## Memory

A reader takes about 155 KiB (`prel_reader_size()`): it holds `manifest.json` (up to 64 KiB) and
`manifest.sig` (up to 8 KiB) whole, because Ed25519 signs the exact bytes, plus 4 096 parsed JSON
values. Payloads stream through a 1 KiB buffer whatever their size.

## Building

```bash
cmake -S c -B c/build && cmake --build c/build
ctest --test-dir c/build        # every case in vectors/
```

Or add it to a CMake project with `add_subdirectory(pelco-release/c)` and link `pelco_release`.
The library needs OpenSSL 1.1.1 or later.

## Crypto backends

SHA-256 and HKDF are built in. Ed25519, X25519, AES key unwrap and AES-GCM come from one backend,
whose interface is `src/prel_crypto.h`. `src/prel_crypto_openssl.c` is the only one so far. An ESP32
backend would use mbedTLS for AES and X25519 and a separate Ed25519 implementation, since mbedTLS
has none.

## Conformance

`run_vectors` checks every case in `vectors/`, feeding each release whole, in uneven pieces and a
byte at a time, and checks the writer received each payload's exact plaintext. CI also runs
`tools/differential.py`, which mutates thousands of manifests at random and checks this reader
reports the same result as the Python reference for every one.
