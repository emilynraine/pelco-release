# Pelco release format — version 1

This is the normative definition of a Pelco firmware release: what a release file contains, how it
is signed and encrypted, and the order in which every installer checks it. The words MUST, MUST NOT,
SHOULD and MAY are used as in RFC 2119.

The format is product-free. It never names a product, component or hardware revision; those facts
belong to each product's definition. An installer supplies them when it checks a release.

## 1. Terms

- **Release:** one component at one version, as a single release file.
- **Component:** one updatable piece of firmware or software, identified as `<product>.<unit>.<part>`,
  for example `duo.button.app`.
- **Unit:** one physical device that a component is installed on, for example one Duo button.
- **Installer:** whatever checks a release and installs it: a device itself, a parent device such as
  a controller, a host app such as PelcoOne, or a factory station.
- **Verifier:** anything that checks a release without installing it, such as PelcoHub on upload.
- **Writer:** the product-specific code an installer streams the decrypted image into.

## 2. The release file

A release file is an uncompressed POSIX ustar archive. Its file name SHOULD be
`<component>-<version>.prel`.

It MUST contain exactly these entries, in this order:

1. `manifest.json`
2. `manifest.sig`
3. one entry per payload, named and ordered as in the manifest's `payload` array.

Every entry MUST be a regular file. Directories, links, extended headers and any other entry are
not allowed. Entry names match `^[A-Za-z0-9._-]{1,64}$`.

Each entry header MUST have the POSIX magic `ustar\0` and version `00`, type flag `0` or NUL, an
empty name prefix, a size in octal and a correct checksum. Other header fields are ignored. The
entries are followed by the end-of-archive marker (two zero blocks); only zero bytes may follow it.

`manifest.json` MUST NOT exceed 65 536 bytes. `manifest.sig` MUST NOT exceed 8 192 bytes.

The manifest and its signature come first so that an installer reading the file as a stream can
check them before any payload arrives.

An installer that receives the parts separately (for example a manifest, a signature and a payload
uploaded one by one) MUST apply the same checks to the same bytes.

## 3. The manifest

`manifest.json` is a UTF-8 JSON object. Its schema is `schema/manifest.schema.json`. All binary
values are lowercase hexadecimal.

`manifest.json` and `manifest.sig` MUST be valid UTF-8 without a byte order mark, and MUST NOT
repeat a member name within an object. Readers reject a repeated name rather than picking one, so
two readers can never see different values in the same signed manifest.

| Field | Required | Meaning |
| --- | --- | --- |
| `format` | yes | Always `"pelco-release"`. |
| `format_version` | yes | `1` for this document. |
| `product` | yes | Product ID, for example `"duo"`. |
| `component` | yes | Component ID. MUST start with `product` followed by `.`. |
| `version` | yes | Semantic Versioning 2.0.0 without build metadata, for example `"2.3.0"` or `"2.3.0-rc.1"`. Releases are ordered by semver precedence. |
| `reported_version` | yes | The exact string the unit reports after this release is installed. Installers compare it as an opaque string. |
| `channel` | yes | `"test"` or `"release"`. A `release` version MUST NOT have a pre-release part. |
| `hardware` | yes | Hardware IDs the release may be installed on. Non-empty, no duplicates. |
| `requires` | no | Versions of other components that must be installed (section 3.1). |
| `routes` | yes | How the release may reach a unit (section 3.2). Non-empty, no duplicates. |
| `payload` | yes | The files the release installs (section 3.3). Non-empty. |
| `recipients` | if any payload is encrypted | Who can decrypt it (section 5). |
| `build` | yes | Where the release came from (section 3.4). |

### 3.1 Requirements

Each entry in `requires` is:

| Field | Required | Meaning |
| --- | --- | --- |
| `component` | yes | The component that must be installed. |
| `scope` | yes | `"unit"`: on the same unit as this release's target. `"system"`: anywhere in the installed system the target belongs to, for example the controller a button is attached to. |
| `min` | at least one of `min`, `max_exclusive` | Lowest acceptable version, inclusive. |
| `max_exclusive` | | First unacceptable version. |

A requirement is met only when the installer knows the installed version of that component in that
scope and it falls in range. An unknown version does not meet a requirement.

Installed versions are compared as semver. Turning what a unit reports into a semver version is the
product's job, defined in its product definition; the format only fixes how the results compare. A
reported version the product can't turn into semver counts as unknown.

### 3.2 Routes

`routes` lists how the release may reach a unit. Known values are in `registry/routes.json`. An
installer MUST NOT install over a route the release doesn't list, and ignores values it doesn't
know.

### 3.3 Payloads

Each entry in `payload` is:

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Entry name in the release file. Unique within the release. |
| `type` | yes | What the file is. Known values are in `registry/payload-types.json`. |
| `size` | yes | Size in bytes of the entry as stored in the release file. |
| `sha256` | yes | SHA-256 of the entry as stored. |
| `encryption` | no | Present if the entry is encrypted (section 4). |
| `plain_size` | if encrypted | Size of the decrypted image. MUST be absent if not encrypted. |
| `plain_sha256` | if encrypted | SHA-256 of the decrypted image. MUST be absent if not encrypted. |

An installer that doesn't know a payload's `type` MUST refuse the release.

### 3.4 Build

| Field | Required | Meaning |
| --- | --- | --- |
| `source` | yes | Repository and tag the release was built from, for example `"guardian-duo@v2.3.0"`. |
| `commit` | yes | Full commit hash. |
| `built_at` | yes | RFC 3339 timestamp, UTC. |

### 3.5 Unknown fields and new versions

Readers MUST ignore fields they don't know, at every level. A change that a reader must understand
to install safely MUST increase `format_version`. Readers MUST refuse a `format_version` they
don't support.

## 4. Payload encryption

Encryption is optional per payload. When used, every encrypted payload in a release uses the same
32-byte **content key**, generated at random for that release. It MUST NOT be reused for any other
release.

`encryption` is:

| Field | Meaning |
| --- | --- |
| `alg` | `"aes-256-gcm-chunked"`. |
| `chunk_size` | Plaintext bytes per chunk, from 1 024 to 1 048 576. |
| `nonce_prefix` | 8 random bytes (16 hex characters), unique among the release's payloads. |

The plaintext is split into chunks of `chunk_size` bytes; the last chunk may be shorter but is never
empty. Chunks are numbered from 0. Chunk *i* is encrypted with AES-256-GCM:

- key: the content key;
- nonce (12 bytes): `nonce_prefix` followed by *i* as a 4-byte big-endian integer;
- additional authenticated data (1 byte): `0x01` for the last chunk, `0x00` for every other chunk;
- output: the ciphertext followed by its 16-byte tag.

The stored entry is the concatenation of every chunk's output, in order. Its `size` is therefore
`plain_size + 16 × ceil(plain_size / chunk_size)`.

The last-chunk flag stops a truncated payload from decrypting as a shorter valid one. The per-chunk
tag lets a device decrypt and authenticate as it receives, without holding the whole image.

## 5. Recipients

`recipients` lists who can decrypt the release. Each entry carries the content key wrapped for one
recipient key:

| Field | Meaning |
| --- | --- |
| `key_id` | The recipient key's ID. Unique within the release. |
| `alg` | `"x25519-hkdf-sha256-aes-kw"`. |
| `ephemeral_pub` | A fresh X25519 public key for this entry, 32 bytes. |
| `wrapped_key` | The wrapped content key, 40 bytes. |

To wrap, the release builder, for each recipient:

1. generates a fresh X25519 key pair (`eph_priv`, `eph_pub`);
2. computes `shared = X25519(eph_priv, recipient_pub)`;
3. derives `kek = HKDF-SHA256(ikm = shared, salt = eph_pub || recipient_pub, info = "pelco-release v1 kek" || key_id, length = 32)`,
   where `key_id` is its UTF-8 bytes;
4. sets `wrapped_key = AES-256-KW(kek, content_key)` (RFC 3394).

To unwrap, an installer holding the private key for `key_id` computes `shared = X25519(recipient_priv, ephemeral_pub)`,
derives `kek` the same way, and unwraps. An all-zero `shared` value MUST be rejected.

A recipient key is held by whatever decrypts: a device, a parent device, a host app or a factory
station. Release-signing keys and recipient keys are always separate key pairs.

## 6. The signature

`manifest.sig` is a UTF-8 JSON object, schema `schema/signature.schema.json`:

```json
{
  "format": "pelco-release-signature",
  "format_version": 1,
  "signatures": [
    { "key_id": "duo-release-2026", "alg": "ed25519", "sig": "…128 hex characters…" }
  ]
}
```

Each signature is Ed25519 (RFC 8032, pure, not pre-hashed) over the **exact bytes** of
`manifest.json` as stored in the release file. The manifest is never re-serialised or canonicalised
for signing or checking.

Several signatures are allowed so a release can be signed by an old and a new key while keys rotate.

### 6.1 Keyrings

A verifier holds a keyring, schema `schema/keyring.schema.json`. Each key states what it may sign:

| Field | Meaning |
| --- | --- |
| `key_id` | The key's ID. |
| `alg` | `"ed25519"`. |
| `public_key` | 32 bytes. |
| `channels` | Channels it may sign, for example `["test"]`. |
| `products` | Products it may sign, for example `["duo"]`. |
| `not_after` | Optional. RFC 3339 timestamp after which the key is no longer trusted for new releases, judged against `build.built_at`. |

A signature counts only if its key is in the keyring, the signature verifies, and the key is allowed
to sign the manifest's `channel` and `product`.

`not_after` is for routine rotation. It can't stop a stolen key, which could sign a manifest with an
earlier `built_at`. A compromised key is removed from every keyring.

## 7. Checking a release

Every installer and verifier checks a release in this order and stops at the first failure,
reporting that result code (`result-codes.json`). Steps that need knowledge of the target (from
step 6 on) apply only to installers; a verifier such as PelcoHub stops after step 5.

1. **Container.** The release file starts with `manifest.json` then `manifest.sig`, as section 2
   requires, within the size limits. → `RELEASE_MALFORMED`
2. **Signature.** At least one signature in `manifest.sig` is by a key in the keyring and verifies
   over the exact manifest bytes. Nothing in the manifest is trusted before this step passes.
   → `SIGNATURE_MALFORMED`, `KEY_UNKNOWN`, `SIGNATURE_INVALID`
3. **Format.** The manifest is JSON with `format` `"pelco-release"` and a supported
   `format_version`. → `MANIFEST_INVALID`, `FORMAT_UNSUPPORTED`
4. **Manifest.** The manifest satisfies the schema and every rule in sections 3 to 5.
   → `MANIFEST_INVALID`
5. **Key permission.** A verifying signature's key is allowed to sign this `channel` and `product`,
   and is within its `not_after`. → `KEY_NOT_PERMITTED`
6. **Channel.** The installer accepts this channel. Installers accept `test` releases only when
   configured for testing. → `CHANNEL_NOT_ALLOWED`
7. **Target.** `component` is the component being updated. → `WRONG_COMPONENT`
8. **Hardware.** The target unit's hardware ID is in `hardware`. → `HARDWARE_INCOMPATIBLE`
9. **Route.** The route being used is in `routes`. → `ROUTE_NOT_ALLOWED`
10. **Requirements.** Every entry in `requires` is met. → `REQUIREMENT_NOT_MET`
11. **Version.** Compared with the version installed on the target: newer passes; equal fails with
    `ALREADY_INSTALLED` unless the caller asked to reinstall; older fails with
    `DOWNGRADE_NOT_ALLOWED` unless the caller passed the downgrade flag. If the installed version is
    unknown the step passes, so a unit whose firmware can't report one can still be recovered.
12. **Payload types.** The installer knows every payload's `type`. → `PAYLOAD_TYPE_UNSUPPORTED`
13. **Recipient.** If any payload is encrypted, the installer holds a private key for one of the
    `recipients` and unwraps the content key. → `NO_RECIPIENT_KEY`, `KEY_UNWRAP_FAILED`
14. **Payload.** Each payload's entry follows in manifest order, and after the last one comes the
    end of the archive (`RELEASE_MALFORMED`). As each payload is read: its stored size and SHA-256
    match; if encrypted, every chunk authenticates and the decrypted size and SHA-256 match.
    → `PAYLOAD_SIZE_MISMATCH`, `PAYLOAD_HASH_MISMATCH`, `DECRYPT_FAILED`, `PLAIN_HASH_MISMATCH`

    A reader decrypting as it receives may find a bad chunk before the stored hash is complete. A
    changed encrypted payload can therefore report `DECRYPT_FAILED` or `PAYLOAD_HASH_MISMATCH`;
    both mean the payload was altered.

### 7.1 Nothing is activated early

Decrypted bytes MAY be written to the target while step 14 is still running, for example straight
into an inactive flash slot. A writer MUST NOT make the new image bootable, active or visible until
every step has passed for every payload. If any step fails, the writer aborts and the target keeps
running what it had.

### 7.2 Where checks run

Every party that handles a release checks it as far as it can:

- PelcoHub, on upload: steps 1–5.
- A host such as PelcoOne, before sending: steps 1–12, using the versions it has read from the target.
- A device or parent device that installs: all steps. It is the final authority.

A host that installs onto a unit that can't check releases itself (for example over a serial
bootloader) is that unit's installer and runs all steps.

## 8. Conformance

`vectors/` holds a release file for each case a reader must handle, with the context to check it in
and the result code it must report. A reader conforms when it reports the expected code for every
case. `pelco_release/` is the reference implementation the vectors are checked against.

## 9. Ownership

This format and its test cases are owned by `pelco-release`. Product facts (component IDs, hardware
IDs and how a unit reports them, which routes reach a product, who holds which recipient keys) are
owned by each product's definition, never by this repository.
