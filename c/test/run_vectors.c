/*
 * Runs every case in vectors/ through the C reader: the whole file at once, in uneven pieces, and a
 * byte at a time. An installer's writer must receive each payload's exact plaintext and be committed
 * only on OK, aborted otherwise.
 *
 *     run_vectors <path to vectors/>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pelco_release.h"
#include "prel_json.h"
#include "prel_sha256.h"

#define MAX_KEYS 32
#define MAX_LIST 32

static char dir[1024];

static uint8_t *read_file(const char *name, size_t *len)
{
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "can't open %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)size + 1);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) exit(2);
    fclose(f);
    *len = (size_t)size;
    return buf;
}

static void parse(prel_json *doc, const char *name)
{
    size_t len;
    uint8_t *buf = read_file(name, &len);
    prel_json_node *nodes = malloc(65535 * sizeof *nodes);
    if (!nodes || !prel_json_parse(doc, buf, len, nodes, 65535, 64)) {
        fprintf(stderr, "can't parse %s\n", name);
        exit(2);
    }
}

static void hex(uint8_t *out, const char *s, size_t bytes)
{
    for (size_t i = 0; i < bytes; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static const char *str(const prel_json *d, size_t object, const char *name)
{
    size_t n = prel_json_get(d, object, name);
    return n ? prel_json_str(d, n) : NULL;
}

static bool flag(const prel_json *d, size_t object, const char *name)
{
    return prel_json_is(d, prel_json_get(d, object, name), PREL_JSON_TRUE);
}

/* ---- keys -------------------------------------------------------------------------------------- */

static prel_signing_key keyring[MAX_KEYS];
static const char *products[MAX_KEYS][MAX_LIST];
static size_t keyring_count;

typedef struct {
    const char *key_id;
    uint8_t private_key[32];
} x25519_key;
static x25519_key x25519_keys[MAX_KEYS];
static size_t x25519_count;

static void load_keys(void)
{
    static prel_json ring, keys;
    parse(&ring, "keyring.json");
    for (size_t k = prel_json_first(&ring, prel_json_get(&ring, 0, "keys")); k; k = prel_json_next(&ring, k)) {
        prel_signing_key *key = &keyring[keyring_count];
        key->key_id = str(&ring, k, "key_id");
        hex(key->public_key, str(&ring, k, "public_key"), 32);
        key->not_after = str(&ring, k, "not_after");
        for (size_t c = prel_json_first(&ring, prel_json_get(&ring, k, "channels")); c; c = prel_json_next(&ring, c))
            key->channels |= prel_json_str_eq(&ring, c, "test") ? PREL_CHANNEL_TEST : PREL_CHANNEL_RELEASE;
        for (size_t p = prel_json_first(&ring, prel_json_get(&ring, k, "products")); p; p = prel_json_next(&ring, p))
            products[keyring_count][key->product_count++] = prel_json_str(&ring, p);
        key->products = products[keyring_count++];
    }
    parse(&keys, "test-keys.json");
    for (size_t k = prel_json_first(&keys, prel_json_get(&keys, 0, "keys")); k; k = prel_json_next(&keys, k)) {
        if (strcmp(str(&keys, k, "alg"), "x25519") != 0) continue;
        x25519_keys[x25519_count].key_id = str(&keys, k, "key_id");
        hex(x25519_keys[x25519_count++].private_key, str(&keys, k, "private_key"), 32);
    }
}

/* ---- a writer that checks what it receives ----------------------------------------------------- */

typedef struct {
    prel_sha256 hash;
    uint8_t expected[32];
    uint64_t expected_size, received;
    bool open;
    int bad, commits, aborts;
} test_writer;

static void close_payload(test_writer *w)
{
    uint8_t digest[32];
    if (!w->open) return;
    prel_sha256_final(&w->hash, digest);
    if (memcmp(digest, w->expected, 32) != 0 || w->received != w->expected_size) w->bad++;
    w->open = false;
}

static int w_begin(void *user, const prel_payload_info *p)
{
    test_writer *w = user;
    close_payload(w);
    prel_sha256_init(&w->hash);
    memcpy(w->expected, p->plain_sha256, 32);
    w->expected_size = p->plain_size;
    w->received = 0;
    w->open = true;
    return 0;
}

static int w_write(void *user, const uint8_t *data, size_t len)
{
    test_writer *w = user;
    prel_sha256_update(&w->hash, data, len);
    w->received += len;
    return 0;
}

static void w_commit(void *user)
{
    test_writer *w = user;
    close_payload(w);
    w->commits++;
}

static void w_abort(void *user)
{
    ((test_writer *)user)->aborts++;
}

/* ---- running a case ---------------------------------------------------------------------------- */

static void *memory;

static prel_result run(const prel_context *ctx, const uint8_t *data, size_t len, const size_t *pieces,
                       test_writer *w, const char **detail)
{
    prel_writer writer = {w, w_begin, w_write, w_commit, w_abort};
    prel_reader *r = prel_reader_init(memory, prel_reader_size(), ctx, &writer);
    prel_result res = PREL_PENDING;
    size_t at = 0;
    for (size_t i = 0; at < len && res == PREL_PENDING; i++) {
        size_t n = pieces ? pieces[i % 7] : len;
        if (n > len - at) n = len - at;
        res = prel_reader_feed(r, data + at, n);
        at += n;
    }
    if (res == PREL_PENDING) res = prel_reader_finish(r);
    if (res == PREL_OK && !prel_reader_manifest(r)) res = PREL_WRITER_FAILED;
    *detail = prel_reader_detail(r);
    prel_reader_release(r);
    return res;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: run_vectors <vectors directory>\n");
        return 2;
    }
    snprintf(dir, sizeof dir, "%s", argv[1]);
    memory = malloc(prel_reader_size());
    load_keys();

    static prel_json v;
    parse(&v, "vectors.json");
    static const size_t uneven[7] = {1, 7, 511, 512, 513, 4096, 100000};
    static const size_t one[7] = {1, 1, 1, 1, 1, 1, 1};
    const size_t *feeds[3] = {NULL, uneven, one};
    const char *feed_names[3] = {"whole", "uneven pieces", "byte by byte"};
    int cases = 0, failures = 0;

    for (size_t c = prel_json_first(&v, prel_json_get(&v, 0, "cases")); c; c = prel_json_next(&v, c)) {
        size_t cx = prel_json_get(&v, c, "context");
        const char *name = str(&v, c, "name"), *expected = str(&v, c, "expected"), *checks = str(&v, cx, "checks");
        prel_context ctx = {0};
        prel_installed unit[MAX_LIST], system[MAX_LIST];
        const char *types[MAX_LIST];
        prel_recipient_key recipients[MAX_LIST];

        ctx.checks = strcmp(checks, "verifier") == 0 ? PREL_CHECKS_VERIFIER
                   : strcmp(checks, "host") == 0   ? PREL_CHECKS_HOST
                                                    : PREL_CHECKS_INSTALLER;
        ctx.keyring = keyring;
        ctx.keyring_count = keyring_count;
        ctx.accept_test = flag(&v, cx, "accept_test");
        ctx.component = str(&v, cx, "component");
        ctx.hardware = str(&v, cx, "hardware");
        ctx.route = str(&v, cx, "route");
        ctx.reinstall = flag(&v, cx, "reinstall");
        ctx.allow_downgrade = flag(&v, cx, "allow_downgrade");
        size_t installed = prel_json_get(&v, cx, "installed");
        for (size_t s = 0; s < 2; s++) {
            prel_installed *list = s ? system : unit;
            size_t *count = s ? &ctx.system_count : &ctx.unit_count;
            size_t scope = prel_json_get(&v, installed, s ? "system" : "unit");
            for (size_t i = prel_json_first(&v, scope); i; i = prel_json_next(&v, i)) {
                list[*count].component = v.text + v.nodes[i].key_start;
                list[(*count)++].version = prel_json_str(&v, i);
            }
        }
        ctx.unit = unit;
        ctx.system = system;
        for (size_t t = prel_json_first(&v, prel_json_get(&v, cx, "payload_types")); t; t = prel_json_next(&v, t))
            types[ctx.payload_type_count++] = prel_json_str(&v, t);
        ctx.payload_types = types;
        for (size_t k = prel_json_first(&v, prel_json_get(&v, cx, "recipient_keys")); k; k = prel_json_next(&v, k)) {
            for (size_t i = 0; i < x25519_count; i++) {
                if (strcmp(x25519_keys[i].key_id, prel_json_str(&v, k)) != 0) continue;
                recipients[ctx.recipient_key_count].key_id = x25519_keys[i].key_id;
                memcpy(recipients[ctx.recipient_key_count++].private_key, x25519_keys[i].private_key, 32);
            }
        }
        ctx.recipient_keys = recipients;

        size_t len;
        uint8_t *data = read_file(str(&v, c, "file"), &len);
        for (int f = 0; f < 3; f++) {
            test_writer w = {0};
            const char *detail;
            prel_result res = run(&ctx, data, len, feeds[f], &w, &detail);
            bool ok = strcmp(prel_result_name(res), expected) == 0;
            bool ok_result = strcmp(expected, "OK") == 0;
            if (ctx.checks == PREL_CHECKS_INSTALLER)
                ok = ok && !w.bad && w.commits == (ok_result ? 1 : 0) && w.aborts == (ok_result ? 0 : 1);
            else
                ok = ok && w.commits == 0 && w.aborts == 0;
            if (!ok) {
                failures++;
                printf("%s (%s): expected %s, got %s (%s); writer: %d bad, %d commits, %d aborts\n", name,
                       feed_names[f], expected, prel_result_name(res), detail, w.bad, w.commits, w.aborts);
            }
        }
        free(data);
        cases++;
    }
    if (failures) {
        printf("%d failures\n", failures);
        return 1;
    }
    printf("c vectors OK: %d cases, each fed whole, in uneven pieces and byte by byte\n", cases);
    return 0;
}
