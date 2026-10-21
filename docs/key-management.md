# Key management

Who holds which keys, where they live, and what happens when one changes. The format only fixes
what a key may sign (`release-format.md` section 6.1); this document is how Pelco runs it.

## Signing keys

Each product has its own signing keys, named `<product>-<purpose>-<year>`:

| Key | Signs | Private key lives in | Who can use it |
| --- | --- | --- | --- |
| `<product>-test-<year>` | `test` channel | the product repository's `firmware-test` environment | any workflow run in that repository |
| `<product>-release-<year>` | `release` channel | the product repository's `firmware-release` environment | a workflow run on a `v*` tag, after approval |
| `<product>-recovery-<year>` | `release` channel | offline only: the company password manager | the key custodians, by hand, if the release key is lost or stolen |

Every keyring a product ships (in device firmware, the controller, PelcoOne and PelcoHub) lists its
release and recovery keys, and its test key. The recovery key is never loaded into CI, so stealing
the CI key can't also take the way to replace it.

### Custodians and approval

- **Custodians:** the firmware owner and one named backup. Only they generate keys, hold the
  password manager entries, and edit the environments' secrets.
- **Release approval:** the `firmware-release` environment requires a review from a custodian, with
  "prevent self-review" on, so a release signature always takes two people: whoever tags the release,
  and a custodian who approves it. Its deployments are limited to `v*` tags.
- **Test signing** needs no approval. Installers accept `test` releases only when configured for
  testing, so a test signature can't stand in for a release.

### Creating a key

On a custodian's machine, outside any repository:

```bash
python -m pelco_release keygen signing duo-release-2026 --out duo-release-2026.key --channel release --product duo
```

1. Store the `.key` file's contents in the password manager entry for the product's keys.
2. For test and release keys, paste the same contents as the secret `PELCO_RELEASE_SIGNING_KEY` in
   the matching environment of the product repository.
3. Delete the `.key` file.
4. Add the printed public half to the product's keyring, which its product definition owns.

## Rotation

A new key is made each year, or sooner when a custodian leaves. Devices hold their keyring in
firmware, so the new key must reach them before anything is signed with it:

1. Create the new key and add it to the keyring, alongside the current one.
2. Ship that keyring, signed with the current key, to every party that checks releases.
3. Switch the environment secret to the new key.
4. Set `not_after` on the old key's keyring entry to the switch date. Releases it already signed
   stay valid; it can't sign newer ones.

## A stolen or leaked key

1. Remove the key from the environment and the password manager.
2. Remove it from every keyring, and ship the new keyrings signed with a key that's still trusted:
   the release key if the test key leaked, the recovery key if the release key did.
3. Create a replacement key as above, and decide whether to re-sign the releases the leaked key
   signed.

`not_after` doesn't help here: a thief can sign with any `built_at`. Only removing the key does.

## Recipient keys

A recipient key decrypts payloads. One X25519 key per kind of receiver, per product, for example
`duo-controller-2026` for every Duo controller and `pelcoone-2026` for PelcoOne. Their private keys
are built into the software that holds them, injected at build time from a CI secret, never kept in
a source repository.

Because they ship inside software, a determined attacker can extract them. Encryption keeps
firmware images from being casually copied or read; it is not access control. The signature is what
stops a modified image from installing.

Recipient keys rotate with the software that holds them: a new key is added to `recipients` in new
releases once the software holding it is deployed.
