/*
 * pelco_release: reads and checks Pelco firmware releases (spec/release-format.md).
 *
 * The reader is fed the release file as it arrives, in pieces of any size, and checks it in the
 * order of section 7. An installer passes a writer that receives each payload's decrypted bytes
 * and is told to commit only once every check has passed.
 *
 *     prel_reader *r = prel_reader_init(malloc(prel_reader_size()), prel_reader_size(), &ctx, &writer);
 *     prel_result res = PREL_PENDING;
 *     while (res == PREL_PENDING && (n = receive(buf, sizeof buf)) > 0)
 *         res = prel_reader_feed(r, buf, n);
 *     if (res == PREL_PENDING) res = prel_reader_finish(r);
 *     prel_reader_release(r);
 */
#ifndef PELCO_RELEASE_H
#define PELCO_RELEASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes, numbered as in spec/result-codes.json, plus two values that aren't results. */
typedef enum {
    PREL_PENDING = -1, /* not a result: feed more, or call prel_reader_finish at the end of input */
    PREL_OK = 0,
    PREL_RELEASE_MALFORMED = 1,
    PREL_SIGNATURE_MALFORMED = 2,
    PREL_KEY_UNKNOWN = 3,
    PREL_SIGNATURE_INVALID = 4,
    PREL_FORMAT_UNSUPPORTED = 5,
    PREL_MANIFEST_INVALID = 6,
    PREL_KEY_NOT_PERMITTED = 7,
    PREL_CHANNEL_NOT_ALLOWED = 8,
    PREL_WRONG_COMPONENT = 9,
    PREL_HARDWARE_INCOMPATIBLE = 10,
    PREL_ROUTE_NOT_ALLOWED = 11,
    PREL_REQUIREMENT_NOT_MET = 12,
    PREL_ALREADY_INSTALLED = 13,
    PREL_DOWNGRADE_NOT_ALLOWED = 14,
    PREL_PAYLOAD_TYPE_UNSUPPORTED = 15,
    PREL_NO_RECIPIENT_KEY = 16,
    PREL_KEY_UNWRAP_FAILED = 17,
    PREL_PAYLOAD_SIZE_MISMATCH = 18,
    PREL_PAYLOAD_HASH_MISMATCH = 19,
    PREL_DECRYPT_FAILED = 20,
    PREL_PLAIN_HASH_MISMATCH = 21,
    PREL_WRITER_FAILED = 100, /* not a format result: the writer refused, or the crypto backend failed */
} prel_result;

/* "OK", "RELEASE_MALFORMED", ...: the spec's name for a result. */
const char *prel_result_name(prel_result result);

typedef enum {
    PREL_CHECKS_VERIFIER, /* steps 1-5, for example PelcoHub on upload */
    PREL_CHECKS_HOST,     /* steps 1-12, for a host before it sends a release on */
    PREL_CHECKS_INSTALLER /* every step */
} prel_checks;

#define PREL_CHANNEL_TEST 1u
#define PREL_CHANNEL_RELEASE 2u

/* A keyring entry: a signing key and what it may sign. */
typedef struct {
    const char *key_id;
    uint8_t public_key[32];
    unsigned channels; /* PREL_CHANNEL_* */
    const char *const *products;
    size_t product_count;
    const char *not_after; /* RFC 3339 UTC, or NULL */
} prel_signing_key;

/* A recipient key the installer holds. */
typedef struct {
    const char *key_id;
    uint8_t private_key[32];
} prel_recipient_key;

/* An installed component's version as semver, after the product's own mapping (section 3.1). */
typedef struct {
    const char *component;
    const char *version;
} prel_installed;

/* What the reader knows about its target. Everything it points to must outlive the reader. */
typedef struct {
    prel_checks checks;
    const prel_signing_key *keyring;
    size_t keyring_count;
    bool accept_test;
    const char *component;
    const char *hardware;
    const char *route;
    const prel_installed *unit;   /* versions on the target unit, including the component itself */
    size_t unit_count;
    const prel_installed *system; /* versions elsewhere in the system the unit belongs to */
    size_t system_count;
    const char *const *payload_types;
    size_t payload_type_count;
    const prel_recipient_key *recipient_keys;
    size_t recipient_key_count;
    bool reinstall;
    bool allow_downgrade;
} prel_context;

typedef struct {
    const char *name;
    const char *type;
    uint64_t plain_size;
    uint8_t plain_sha256[32]; /* of the bytes the writer will receive */
} prel_payload_info;

/*
 * Receives decrypted payloads. Only an installer writes. begin and write return 0 to continue.
 * Bytes written are not yet trusted: commit is called once every check has passed for every
 * payload, abort on any failure (section 7.1).
 */
typedef struct {
    void *user;
    int (*begin)(void *user, const prel_payload_info *payload);
    int (*write)(void *user, const uint8_t *data, size_t len);
    void (*commit)(void *user);
    void (*abort)(void *user);
} prel_writer;

/* Fields of a manifest that has passed every check its reader runs before the payloads. */
typedef struct {
    const char *product;
    const char *component;
    const char *version;
    const char *reported_version;
    const char *channel;
    size_t payload_count;
} prel_manifest_info;

typedef struct prel_reader prel_reader;

/* Bytes a reader needs (about 155 KiB: the manifest and signature are held whole). */
size_t prel_reader_size(void);

/* Starts a reader in caller-supplied memory, aligned as malloc aligns. NULL if too small. */
prel_reader *prel_reader_init(void *memory, size_t size, const prel_context *ctx,
                              const prel_writer *writer);

/* PREL_PENDING while more input is needed; otherwise the final result, which later calls repeat. */
prel_result prel_reader_feed(prel_reader *reader, const uint8_t *data, size_t len);

/* At the end of input: the final result. */
prel_result prel_reader_finish(prel_reader *reader);

/* The manifest once its checks have passed, else NULL. Valid until the reader is released. */
const prel_manifest_info *prel_reader_manifest(const prel_reader *reader);

/* What failed, for logs: a short English phrase, or "" if nothing has. */
const char *prel_reader_detail(const prel_reader *reader);

/* Frees backend state and wipes key material. The memory itself belongs to the caller. */
void prel_reader_release(prel_reader *reader);

#ifdef __cplusplus
}
#endif

#endif
