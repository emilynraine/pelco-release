#include "pelco_release.h"

#include <string.h>

#include "prel_crypto.h"
#include "prel_json.h"
#include "prel_sha256.h"

#define MANIFEST_MAX 65536
#define SIGNATURE_MAX 8192
#define MAX_VALUES 4096
#define MAX_DEPTH 32
#define MAX_SIGNATURES 8
#define MAX_SIZE 8589934591ULL
#define TAG 16
#define BLOCK 512
#define SCRATCH 1024
#define KEK_INFO "pelco-release v1 kek"

enum { S_HEADER, S_DATA, S_PAD, S_END, S_TRAILER };

struct prel_reader {
    const prel_context *ctx;
    prel_writer writer;
    bool has_writer;
    prel_result result;
    const char *detail;

    /* the archive */
    int state;
    uint8_t block[BLOCK];
    size_t block_fill;
    uint64_t entry_left;
    size_t pad_left;
    unsigned entry; /* 0 manifest.json, 1 manifest.sig, then payloads */
    size_t manifest_len, sig_len;

    /* the manifest, once checked */
    prel_json doc;
    bool have_info;
    prel_manifest_info info;
    size_t payload; /* node of the payload being read, or of the next one */
    size_t payloads_read;
    uint8_t content_key[32];

    /* the payload being read */
    prel_payload_info pinfo;
    uint8_t sha256[32];
    bool encrypted;
    uint64_t chunk_size;
    uint8_t nonce_prefix[8];
    uint64_t chunk, chunk_count, ct_left;
    uint8_t tag[TAG];
    size_t tag_fill;
    prel_sha256 stored_hash, plain_hash;
    prel_gcm *gcm;
    uint8_t scratch[SCRATCH];

    uint8_t manifest[MANIFEST_MAX];
    uint8_t sig[SIGNATURE_MAX];
    prel_json_node nodes[MAX_VALUES];
};

static const char *const NAMES[] = {
    "OK", "RELEASE_MALFORMED", "SIGNATURE_MALFORMED", "KEY_UNKNOWN", "SIGNATURE_INVALID",
    "FORMAT_UNSUPPORTED", "MANIFEST_INVALID", "KEY_NOT_PERMITTED", "CHANNEL_NOT_ALLOWED",
    "WRONG_COMPONENT", "HARDWARE_INCOMPATIBLE", "ROUTE_NOT_ALLOWED", "REQUIREMENT_NOT_MET",
    "ALREADY_INSTALLED", "DOWNGRADE_NOT_ALLOWED", "PAYLOAD_TYPE_UNSUPPORTED", "NO_RECIPIENT_KEY",
    "KEY_UNWRAP_FAILED", "PAYLOAD_SIZE_MISMATCH", "PAYLOAD_HASH_MISMATCH", "DECRYPT_FAILED",
    "PLAIN_HASH_MISMATCH",
};

const char *prel_result_name(prel_result result)
{
    if (result == PREL_PENDING) return "PENDING";
    if (result == PREL_WRITER_FAILED) return "WRITER_FAILED";
    if (result >= 0 && (size_t)result < sizeof NAMES / sizeof NAMES[0]) return NAMES[result];
    return "UNKNOWN";
}

/* ---- outcome ----------------------------------------------------------------------------------- */

static void wipe(prel_reader *r)
{
    memset(r->content_key, 0, sizeof r->content_key);
}

static bool fail(prel_reader *r, prel_result code, const char *detail)
{
    if (r->result != PREL_PENDING) return false;
    r->result = code;
    r->detail = detail;
    wipe(r);
    if (r->has_writer && r->writer.abort) r->writer.abort(r->writer.user);
    return false;
}

static void succeed(prel_reader *r)
{
    r->result = PREL_OK;
    wipe(r);
    if (r->has_writer && r->writer.commit) r->writer.commit(r->writer.user);
}

/* ---- text rules -------------------------------------------------------------------------------- */

static bool lower_alnum(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

/* [a-z0-9][a-z0-9<extra>]{0,max-1} */
static bool id_text(const char *s, size_t n, size_t max, bool dot)
{
    if (n < 1 || n > max || !lower_alnum(s[0])) return false;
    for (size_t i = 1; i < n; i++)
        if (!lower_alnum(s[i]) && s[i] != '-' && !(dot && s[i] == '.')) return false;
    return true;
}

static bool component_text(const char *s, size_t n)
{
    size_t parts = 0, start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            if (!id_text(s + start, i - start, 32, false)) return false;
            parts++;
            start = i + 1;
        }
    }
    return parts == 3;
}

static bool hex_text(const char *s, size_t n, size_t len)
{
    if (n != len) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static bool printable_text(const char *s, size_t n, char lo, size_t max)
{
    if (n < 1 || n > max) return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < lo || s[i] > 0x7E) return false;
    return true;
}

static bool entry_name_text(const char *s, size_t n)
{
    if (n < 1 || n > 64) return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.'
              || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool digits(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9') return false;
    return true;
}

/* YYYY-MM-DDTHH:MM:SS(.f+)?Z */
static bool time_text(const char *s, size_t n)
{
    if (n < 20 || s[n - 1] != 'Z') return false;
    if (!(digits(s, 4) && s[4] == '-' && digits(s + 5, 2) && s[7] == '-' && digits(s + 8, 2)
          && s[10] == 'T' && digits(s + 11, 2) && s[13] == ':' && digits(s + 14, 2) && s[16] == ':'
          && digits(s + 17, 2)))
        return false;
    if (n == 20) return true;
    return s[19] == '.' && n > 21 && digits(s + 20, n - 21);
}

/* Compares two valid timestamps as instants. */
static int time_cmp(const char *a, size_t an, const char *b, size_t bn)
{
    int c = memcmp(a, b, 19);
    if (c) return c;
    const char *af = an > 20 ? a + 20 : "", *bf = bn > 20 ? b + 20 : "";
    size_t al = an > 20 ? an - 21 : 0, bl = bn > 20 ? bn - 21 : 0;
    for (size_t i = 0; i < al || i < bl; i++) {
        char x = i < al ? af[i] : '0', y = i < bl ? bf[i] : '0';
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

/* ---- semantic versions ------------------------------------------------------------------------- */

typedef struct {
    const char *core[3];
    size_t core_len[3];
    const char *pre;
    size_t pre_len; /* 0: no pre-release */
} semver;

static bool numeric_id(const char *s, size_t n)
{
    return n > 0 && digits(s, n) && (n == 1 || s[0] != '0');
}

static bool pre_id(const char *s, size_t n)
{
    if (n == 0) return false;
    if (digits(s, n)) return numeric_id(s, n);
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

static bool semver_parse(const char *s, size_t n, semver *v)
{
    size_t core_end = n;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '-') {
            core_end = i;
            break;
        }
    size_t part = 0, start = 0;
    for (size_t i = 0; i <= core_end; i++) {
        if (i == core_end || s[i] == '.') {
            if (part == 3 || !numeric_id(s + start, i - start)) return false;
            v->core[part] = s + start;
            v->core_len[part++] = i - start;
            start = i + 1;
        }
    }
    if (part != 3) return false;
    v->pre = NULL;
    v->pre_len = 0;
    if (core_end == n) return true;
    v->pre = s + core_end + 1;
    v->pre_len = n - core_end - 1;
    start = 0;
    for (size_t i = 0; i <= v->pre_len; i++) {
        if (i == v->pre_len || v->pre[i] == '.') {
            if (!pre_id(v->pre + start, i - start)) return false;
            start = i + 1;
        }
    }
    return true;
}

static bool semver_text(const char *s, size_t n, bool release_only)
{
    semver v;
    return semver_parse(s, n, &v) && (!release_only || v.pre_len == 0);
}

static int numeric_cmp(const char *a, size_t an, const char *b, size_t bn)
{
    if (an != bn) return an < bn ? -1 : 1;
    int c = memcmp(a, b, an);
    return (c > 0) - (c < 0);
}

static int ident_cmp(const char *a, size_t an, const char *b, size_t bn)
{
    bool a_num = digits(a, an), b_num = digits(b, bn);
    if (a_num && b_num) return numeric_cmp(a, an, b, bn);
    if (a_num != b_num) return a_num ? -1 : 1;
    int c = memcmp(a, b, an < bn ? an : bn);
    if (c) return (c > 0) - (c < 0);
    return (an > bn) - (an < bn);
}

static size_t ident_len(const char *s, size_t n)
{
    size_t i = 0;
    while (i < n && s[i] != '.') i++;
    return i;
}

/* Precedence of two valid versions: -1, 0 or 1. */
static int semver_cmp(const semver *a, const semver *b)
{
    for (int i = 0; i < 3; i++) {
        int c = numeric_cmp(a->core[i], a->core_len[i], b->core[i], b->core_len[i]);
        if (c) return c;
    }
    if (!a->pre_len || !b->pre_len) return (a->pre_len == 0) - (b->pre_len == 0);
    const char *x = a->pre, *y = b->pre;
    size_t xn = a->pre_len, yn = b->pre_len;
    while (xn && yn) {
        size_t xl = ident_len(x, xn), yl = ident_len(y, yn);
        int c = ident_cmp(x, xl, y, yl);
        if (c) return c;
        x += xl;
        xn -= xl;
        y += yl;
        yn -= yl;
        if (xn) x++, xn--;
        if (yn) y++, yn--;
    }
    return (xn > 0) - (yn > 0);
}

/* ---- JSON helpers ------------------------------------------------------------------------------ */

#define STR(n) prel_json_str(&r->doc, (n))
#define LEN(n) prel_json_strlen(&r->doc, (n))
#define IS(n, t) prel_json_is(&r->doc, (n), PREL_JSON_##t)
#define GET(o, name) prel_json_get(&r->doc, (o), (name))
#define FIRST(n) prel_json_first(&r->doc, (n))
#define NEXT(n) prel_json_next(&r->doc, (n))
#define EQ(n, s) prel_json_str_eq(&r->doc, (n), (s))
#define REQUIRE(cond, why) do { if (!(cond)) { *reason = (why); return false; } } while (0)

static bool str_is(const prel_reader *r, size_t n, const char *s, size_t len)
{
    return IS(n, STRING) && LEN(n) == len && memcmp(STR(n), s, len) == 0;
}

static bool strings_unique(const prel_reader *r, size_t array)
{
    for (size_t a = FIRST(array); a; a = NEXT(a))
        for (size_t b = NEXT(a); b; b = NEXT(b))
            if (str_is(r, b, STR(a), LEN(a))) return false;
    return true;
}

static void hex_decode(uint8_t *out, const char *hex, size_t bytes)
{
    for (size_t i = 0; i < bytes; i++) {
        char h = hex[2 * i], l = hex[2 * i + 1];
        out[i] = (uint8_t)(((h <= '9' ? h - '0' : h - 'a' + 10) << 4) | (l <= '9' ? l - '0' : l - 'a' + 10));
    }
}

/* ---- step 4: the schema and the rules of sections 3 to 5 --------------------------------------- */

static bool is_text(const prel_reader *r, size_t n, bool (*rule)(const char *, size_t))
{
    return IS(n, STRING) && rule(STR(n), LEN(n));
}

static bool product_rule(const char *s, size_t n) { return id_text(s, n, 32, false); }
static bool key_id_rule(const char *s, size_t n) { return id_text(s, n, 64, false); }
static bool hardware_rule(const char *s, size_t n) { return id_text(s, n, 64, true); }
static bool semver_rule(const char *s, size_t n) { return semver_text(s, n, false); }
static bool hex64_rule(const char *s, size_t n) { return hex_text(s, n, 64); }

static bool uint_in(const prel_reader *r, size_t n, uint64_t lo, uint64_t hi, uint64_t *out)
{
    uint64_t v = 0;
    if (!prel_json_uint(&r->doc, n, hi, &v) || v < lo) return false;
    if (out) *out = v;
    return true;
}

static bool string_array(const prel_reader *r, size_t n, bool (*rule)(const char *, size_t))
{
    if (!IS(n, ARRAY) || !FIRST(n)) return false;
    for (size_t c = FIRST(n); c; c = NEXT(c))
        if (!is_text(r, c, rule)) return false;
    return strings_unique(r, n);
}

static bool valid_requirement(const prel_reader *r, size_t q, const char **reason)
{
    REQUIRE(IS(q, OBJECT), "requirement isn't an object");
    REQUIRE(is_text(r, GET(q, "component"), component_text), "requirement component");
    size_t scope = GET(q, "scope");
    REQUIRE(EQ(scope, "unit") || EQ(scope, "system"), "requirement scope");
    size_t min = GET(q, "min"), max = GET(q, "max_exclusive");
    REQUIRE(min || max, "requirement has neither min nor max_exclusive");
    REQUIRE(!min || is_text(r, min, semver_rule), "requirement min");
    REQUIRE(!max || is_text(r, max, semver_rule), "requirement max_exclusive");
    return true;
}

static bool valid_payload(const prel_reader *r, size_t p, const char **reason)
{
    REQUIRE(IS(p, OBJECT), "payload isn't an object");
    size_t name = GET(p, "name");
    REQUIRE(IS(name, STRING) && entry_name_text(STR(name), LEN(name)) && !EQ(name, "manifest.json")
                && !EQ(name, "manifest.sig"),
            "payload name");
    REQUIRE(is_text(r, GET(p, "type"), product_rule), "payload type");
    REQUIRE(uint_in(r, GET(p, "size"), 1, MAX_SIZE, NULL), "payload size");
    REQUIRE(is_text(r, GET(p, "sha256"), hex64_rule), "payload sha256");
    size_t enc = GET(p, "encryption"), plain_size = GET(p, "plain_size"), plain_sha = GET(p, "plain_sha256");
    REQUIRE(!plain_size || uint_in(r, plain_size, 1, MAX_SIZE, NULL), "payload plain_size");
    REQUIRE(!plain_sha || is_text(r, plain_sha, hex64_rule), "payload plain_sha256");
    if (!enc) {
        REQUIRE(!plain_size && !plain_sha, "unencrypted payload has plain_size or plain_sha256");
        return true;
    }
    REQUIRE(plain_size && plain_sha, "encrypted payload lacks plain_size or plain_sha256");
    REQUIRE(IS(enc, OBJECT), "encryption isn't an object");
    REQUIRE(EQ(GET(enc, "alg"), "aes-256-gcm-chunked"), "encryption alg");
    REQUIRE(uint_in(r, GET(enc, "chunk_size"), 1024, 1048576, NULL), "encryption chunk_size");
    size_t prefix = GET(enc, "nonce_prefix");
    REQUIRE(IS(prefix, STRING) && hex_text(STR(prefix), LEN(prefix), 16), "encryption nonce_prefix");
    return true;
}

static bool valid_recipient(const prel_reader *r, size_t q, const char **reason)
{
    REQUIRE(IS(q, OBJECT), "recipient isn't an object");
    REQUIRE(is_text(r, GET(q, "key_id"), key_id_rule), "recipient key_id");
    REQUIRE(EQ(GET(q, "alg"), "x25519-hkdf-sha256-aes-kw"), "recipient alg");
    size_t eph = GET(q, "ephemeral_pub"), wrapped = GET(q, "wrapped_key");
    REQUIRE(is_text(r, eph, hex64_rule), "recipient ephemeral_pub");
    REQUIRE(IS(wrapped, STRING) && hex_text(STR(wrapped), LEN(wrapped), 80), "recipient wrapped_key");
    return true;
}

static uint64_t encrypted_size(uint64_t plain, uint64_t chunk)
{
    return plain + TAG * ((plain + chunk - 1) / chunk);
}

static bool valid_manifest(const prel_reader *r, const char **reason)
{
    const size_t m = 0;
    static const char *const required[] = {"format", "format_version", "product", "component",
                                           "version", "reported_version", "channel", "hardware",
                                           "routes", "payload", "build"};
    for (size_t i = 0; i < sizeof required / sizeof required[0]; i++)
        REQUIRE(GET(m, required[i]), "a required field is missing");

    size_t product = GET(m, "product"), component = GET(m, "component"), version = GET(m, "version");
    size_t reported = GET(m, "reported_version"), channel = GET(m, "channel");
    REQUIRE(is_text(r, product, product_rule), "product");
    REQUIRE(is_text(r, component, component_text), "component");
    REQUIRE(is_text(r, version, semver_rule), "version");
    REQUIRE(IS(reported, STRING) && printable_text(STR(reported), LEN(reported), 0x20, 64), "reported_version");
    REQUIRE(EQ(channel, "test") || EQ(channel, "release"), "channel");
    REQUIRE(!EQ(channel, "release") || semver_text(STR(version), LEN(version), true),
            "a release-channel version has a pre-release part");
    REQUIRE(string_array(r, GET(m, "hardware"), hardware_rule), "hardware");
    REQUIRE(string_array(r, GET(m, "routes"), product_rule), "routes");

    size_t requires = GET(m, "requires");
    if (requires) {
        REQUIRE(IS(requires, ARRAY), "requires isn't an array");
        for (size_t q = FIRST(requires); q; q = NEXT(q))
            if (!valid_requirement(r, q, reason)) return false;
    }

    size_t payload = GET(m, "payload");
    REQUIRE(IS(payload, ARRAY) && FIRST(payload), "payload");
    bool any_encrypted = false;
    for (size_t p = FIRST(payload); p; p = NEXT(p)) {
        if (!valid_payload(r, p, reason)) return false;
        any_encrypted = any_encrypted || GET(p, "encryption");
    }

    size_t recipients = GET(m, "recipients");
    if (recipients) {
        REQUIRE(IS(recipients, ARRAY) && FIRST(recipients), "recipients");
        for (size_t q = FIRST(recipients); q; q = NEXT(q))
            if (!valid_recipient(r, q, reason)) return false;
    }
    REQUIRE(!any_encrypted || recipients, "encrypted payloads but no recipients");

    size_t build = GET(m, "build");
    REQUIRE(IS(build, OBJECT), "build");
    size_t commit = GET(build, "commit"), built_at = GET(build, "built_at"), source = GET(build, "source");
    REQUIRE(IS(source, STRING) && printable_text(STR(source), LEN(source), 0x21, 128), "build source");
    REQUIRE(IS(commit, STRING) && (hex_text(STR(commit), LEN(commit), 40) || hex_text(STR(commit), LEN(commit), 64)),
            "build commit");
    REQUIRE(IS(built_at, STRING) && time_text(STR(built_at), LEN(built_at)), "build built_at");

    /* Rules the schema can't express. */
    REQUIRE(LEN(component) > LEN(product) && memcmp(STR(component), STR(product), LEN(product)) == 0
                && STR(component)[LEN(product)] == '.',
            "component doesn't start with the product");
    for (size_t a = FIRST(payload); a; a = NEXT(a)) {
        size_t a_enc = GET(a, "encryption");
        for (size_t b = NEXT(a); b; b = NEXT(b)) {
            REQUIRE(!str_is(r, GET(b, "name"), STR(GET(a, "name")), LEN(GET(a, "name"))),
                    "payload names aren't unique");
            size_t b_enc = GET(b, "encryption");
            REQUIRE(!a_enc || !b_enc || !EQ(GET(b_enc, "nonce_prefix"), STR(GET(a_enc, "nonce_prefix"))),
                    "nonce prefixes aren't unique");
        }
        if (a_enc) {
            uint64_t size = 0, plain = 0, chunk = 1;
            uint_in(r, GET(a, "size"), 1, MAX_SIZE, &size);
            uint_in(r, GET(a, "plain_size"), 1, MAX_SIZE, &plain);
            uint_in(r, GET(a_enc, "chunk_size"), 1024, 1048576, &chunk);
            REQUIRE(size == encrypted_size(plain, chunk), "size doesn't match plain_size and chunk_size");
        }
    }
    for (size_t a = recipients ? FIRST(recipients) : 0; a; a = NEXT(a))
        for (size_t b = NEXT(a); b; b = NEXT(b))
            REQUIRE(!str_is(r, GET(b, "key_id"), STR(GET(a, "key_id")), LEN(GET(a, "key_id"))),
                    "recipient key IDs aren't unique");
    return true;
}

/* ---- steps 2 to 13 ----------------------------------------------------------------------------- */

typedef struct {
    char key_id[65];
    uint8_t sig[64];
} signature;

/* Step 2's parse and schema check; the signatures are copied out before the manifest reuses the nodes. */
static bool read_signatures(prel_reader *r, signature *out, size_t *count)
{
    prel_json sig;
    if (!prel_json_parse(&sig, r->sig, r->sig_len, r->nodes, MAX_VALUES, MAX_DEPTH)) return false;
    uint64_t version;
    size_t list = prel_json_get(&sig, 0, "signatures");
    if (sig.nodes[0].type != PREL_JSON_OBJECT
        || !prel_json_str_eq(&sig, prel_json_get(&sig, 0, "format"), "pelco-release-signature")
        || !prel_json_uint(&sig, prel_json_get(&sig, 0, "format_version"), 1, &version) || version != 1
        || !prel_json_is(&sig, list, PREL_JSON_ARRAY) || sig.nodes[list].len < 1
        || sig.nodes[list].len > MAX_SIGNATURES)
        return false;
    *count = 0;
    for (size_t s = prel_json_first(&sig, list); s; s = prel_json_next(&sig, s)) {
        size_t key_id = prel_json_get(&sig, s, "key_id"), value = prel_json_get(&sig, s, "sig");
        if (!prel_json_is(&sig, s, PREL_JSON_OBJECT) || !prel_json_is(&sig, key_id, PREL_JSON_STRING)
            || !key_id_rule(prel_json_str(&sig, key_id), prel_json_strlen(&sig, key_id))
            || !prel_json_str_eq(&sig, prel_json_get(&sig, s, "alg"), "ed25519")
            || !prel_json_is(&sig, value, PREL_JSON_STRING)
            || !hex_text(prel_json_str(&sig, value), prel_json_strlen(&sig, value), 128))
            return false;
        memcpy(out[*count].key_id, prel_json_str(&sig, key_id), prel_json_strlen(&sig, key_id) + 1);
        hex_decode(out[*count].sig, prel_json_str(&sig, value), 64);
        (*count)++;
    }
    return true;
}

static const prel_signing_key *keyring_find(const prel_context *ctx, const char *key_id)
{
    for (size_t i = 0; i < ctx->keyring_count; i++)
        if (strcmp(ctx->keyring[i].key_id, key_id) == 0) return &ctx->keyring[i];
    return NULL;
}

static bool permitted(const prel_reader *r, const prel_signing_key *key)
{
    size_t channel = GET(0, "channel"), product = GET(0, "product"), built_at = GET(GET(0, "build"), "built_at");
    unsigned bit = EQ(channel, "test") ? PREL_CHANNEL_TEST : PREL_CHANNEL_RELEASE;
    if (!(key->channels & bit)) return false;
    bool product_ok = false;
    for (size_t i = 0; i < key->product_count; i++)
        product_ok = product_ok || str_is(r, product, key->products[i], strlen(key->products[i]));
    if (!product_ok) return false;
    if (!key->not_after) return true;
    size_t n = strlen(key->not_after);
    return time_text(key->not_after, n) && time_cmp(STR(built_at), LEN(built_at), key->not_after, n) <= 0;
}

static const char *installed_version(const prel_installed *list, size_t count, const char *component,
                                     size_t len)
{
    for (size_t i = 0; i < count; i++)
        if (list[i].component && strlen(list[i].component) == len && memcmp(list[i].component, component, len) == 0)
            return list[i].version;
    return NULL;
}

static bool in_string_array(const prel_reader *r, size_t array, const char *s)
{
    if (!s) return false;
    for (size_t c = FIRST(array); c; c = NEXT(c))
        if (str_is(r, c, s, strlen(s))) return true;
    return false;
}

static bool unwrap(prel_reader *r, const prel_recipient_key *key, size_t recipient)
{
    uint8_t eph[32], wrapped[40], own[32], shared[32], kek[32], salt[64], info[sizeof KEK_INFO - 1 + 64];
    size_t key_id = GET(recipient, "key_id"), id_len = LEN(key_id);
    hex_decode(eph, STR(GET(recipient, "ephemeral_pub")), 32);
    hex_decode(wrapped, STR(GET(recipient, "wrapped_key")), 40);
    bool ok = prel_crypto_x25519_public(own, key->private_key)
           && prel_crypto_x25519(shared, key->private_key, eph);
    if (ok) {
        memcpy(salt, eph, 32);
        memcpy(salt + 32, own, 32);
        memcpy(info, KEK_INFO, sizeof KEK_INFO - 1);
        memcpy(info + sizeof KEK_INFO - 1, STR(key_id), id_len);
        prel_hkdf_sha256(kek, salt, 64, shared, 32, info, sizeof KEK_INFO - 1 + id_len);
        ok = prel_crypto_aes256_unwrap(r->content_key, kek, wrapped);
    }
    memset(shared, 0, sizeof shared);
    memset(kek, 0, sizeof kek);
    return ok;
}

static bool check_manifest(prel_reader *r)
{
    const prel_context *ctx = r->ctx;
    const char *reason = "";

    /* 2. Signature */
    signature sigs[MAX_SIGNATURES];
    size_t sig_count = 0, known = 0, signer_count = 0;
    const prel_signing_key *signers[MAX_SIGNATURES];
    if (!read_signatures(r, sigs, &sig_count)) return fail(r, PREL_SIGNATURE_MALFORMED, "manifest.sig is malformed");
    for (size_t i = 0; i < sig_count; i++) {
        const prel_signing_key *key = keyring_find(ctx, sigs[i].key_id);
        if (!key) continue;
        known++;
        if (prel_crypto_ed25519_verify(key->public_key, r->manifest, r->manifest_len, sigs[i].sig))
            signers[signer_count++] = key;
    }
    if (!known) return fail(r, PREL_KEY_UNKNOWN, "no signature is by a key in the keyring");
    if (!signer_count) return fail(r, PREL_SIGNATURE_INVALID, "no signature verifies");

    /* 3. Format */
    if (!prel_json_parse(&r->doc, r->manifest, r->manifest_len, r->nodes, MAX_VALUES, MAX_DEPTH))
        return fail(r, PREL_MANIFEST_INVALID, "manifest.json isn't valid JSON");
    if (r->doc.nodes[0].type != PREL_JSON_OBJECT)
        return fail(r, PREL_MANIFEST_INVALID, "manifest.json isn't a JSON object");
    uint64_t format_version;
    if (!EQ(GET(0, "format"), "pelco-release") || !prel_json_uint(&r->doc, GET(0, "format_version"), 1, &format_version)
        || format_version != 1)
        return fail(r, PREL_FORMAT_UNSUPPORTED, "unsupported format or format_version");

    /* 4. Manifest */
    if (!valid_manifest(r, &reason)) return fail(r, PREL_MANIFEST_INVALID, reason);

    /* 5. Key permission */
    bool allowed = false;
    for (size_t i = 0; i < signer_count; i++) allowed = allowed || permitted(r, signers[i]);
    if (!allowed) return fail(r, PREL_KEY_NOT_PERMITTED, "no verifying key may sign this channel and product");

    size_t payload = GET(0, "payload");
    r->info.product = STR(GET(0, "product"));
    r->info.component = STR(GET(0, "component"));
    r->info.version = STR(GET(0, "version"));
    r->info.reported_version = STR(GET(0, "reported_version"));
    r->info.channel = STR(GET(0, "channel"));
    r->info.payload_count = r->doc.nodes[payload].len;
    if (ctx->checks == PREL_CHECKS_VERIFIER) {
        r->have_info = true;
        return true;
    }

    /* 6 to 9. Channel, target, hardware, route */
    size_t component = GET(0, "component");
    if (EQ(GET(0, "channel"), "test") && !ctx->accept_test)
        return fail(r, PREL_CHANNEL_NOT_ALLOWED, "test releases aren't accepted");
    if (!ctx->component || !str_is(r, component, ctx->component, strlen(ctx->component)))
        return fail(r, PREL_WRONG_COMPONENT, "release is for another component");
    if (!in_string_array(r, GET(0, "hardware"), ctx->hardware))
        return fail(r, PREL_HARDWARE_INCOMPATIBLE, "the unit's hardware isn't listed");
    if (!in_string_array(r, GET(0, "routes"), ctx->route))
        return fail(r, PREL_ROUTE_NOT_ALLOWED, "the route isn't listed");

    /* 10. Requirements */
    size_t requires = GET(0, "requires");
    for (size_t q = requires ? FIRST(requires) : 0; q; q = NEXT(q)) {
        size_t c = GET(q, "component"), min = GET(q, "min"), max = GET(q, "max_exclusive");
        bool unit = EQ(GET(q, "scope"), "unit");
        const char *have = installed_version(unit ? ctx->unit : ctx->system, unit ? ctx->unit_count : ctx->system_count,
                                             STR(c), LEN(c));
        semver installed, bound;
        if (!have || !semver_parse(have, strlen(have), &installed)
            || (min && (semver_parse(STR(min), LEN(min), &bound), semver_cmp(&installed, &bound) < 0))
            || (max && (semver_parse(STR(max), LEN(max), &bound), semver_cmp(&installed, &bound) >= 0)))
            return fail(r, PREL_REQUIREMENT_NOT_MET, "a required component's version is out of range or unknown");
    }

    /* 11. Version: an unknown installed version passes, so a unit that can't report one can be recovered. */
    const char *current = installed_version(ctx->unit, ctx->unit_count, STR(component), LEN(component));
    semver installed, release;
    if (current && semver_parse(current, strlen(current), &installed)) {
        semver_parse(STR(GET(0, "version")), LEN(GET(0, "version")), &release);
        int order = semver_cmp(&release, &installed);
        if (order == 0 && !ctx->reinstall) return fail(r, PREL_ALREADY_INSTALLED, "this version is installed");
        if (order < 0 && !ctx->allow_downgrade) return fail(r, PREL_DOWNGRADE_NOT_ALLOWED, "a newer version is installed");
    }

    /* 12. Payload types */
    bool any_encrypted = false;
    for (size_t p = FIRST(payload); p; p = NEXT(p)) {
        size_t type = GET(p, "type");
        bool known_type = false;
        for (size_t i = 0; i < ctx->payload_type_count; i++)
            known_type = known_type || str_is(r, type, ctx->payload_types[i], strlen(ctx->payload_types[i]));
        if (!known_type) return fail(r, PREL_PAYLOAD_TYPE_UNSUPPORTED, "a payload type isn't supported");
        any_encrypted = any_encrypted || GET(p, "encryption");
    }
    r->have_info = true;
    if (ctx->checks == PREL_CHECKS_HOST) return true;

    /* 13. Recipient */
    if (any_encrypted) {
        bool held = false, unwrapped = false;
        size_t recipients = GET(0, "recipients");
        for (size_t q = FIRST(recipients); q && !unwrapped; q = NEXT(q)) {
            size_t key_id = GET(q, "key_id");
            for (size_t i = 0; i < ctx->recipient_key_count && !unwrapped; i++) {
                const prel_recipient_key *key = &ctx->recipient_keys[i];
                if (!str_is(r, key_id, key->key_id, strlen(key->key_id))) continue;
                held = true;
                unwrapped = unwrap(r, key, q);
            }
        }
        if (!held) return fail(r, PREL_NO_RECIPIENT_KEY, "no recipient key is held");
        if (!unwrapped) return fail(r, PREL_KEY_UNWRAP_FAILED, "the content key doesn't unwrap");
        if (!r->gcm && !(r->gcm = prel_crypto_gcm_new())) return fail(r, PREL_WRITER_FAILED, "crypto backend");
    }
    r->payload = FIRST(payload);
    return true;
}

/* ---- step 14: payloads ------------------------------------------------------------------------- */

static bool start_chunk(prel_reader *r)
{
    uint8_t nonce[12];
    uint64_t plain = r->pinfo.plain_size, offset = r->chunk * r->chunk_size;
    r->ct_left = plain - offset < r->chunk_size ? plain - offset : r->chunk_size;
    r->tag_fill = 0;
    memcpy(nonce, r->nonce_prefix, 8);
    for (int i = 0; i < 4; i++) nonce[8 + i] = (uint8_t)(r->chunk >> (24 - 8 * i));
    if (!prel_crypto_gcm_start(r->gcm, r->content_key, nonce, r->chunk == r->chunk_count - 1))
        return fail(r, PREL_WRITER_FAILED, "crypto backend");
    return true;
}

static bool begin_payload(prel_reader *r, const char *name, uint64_t size)
{
    size_t p = r->payload, enc = GET(p, "encryption");
    uint64_t expected = 0;
    if (!str_is(r, GET(p, "name"), name, strlen(name)))
        return fail(r, PREL_RELEASE_MALFORMED, "a payload entry is missing or out of order");
    uint_in(r, GET(p, "size"), 1, MAX_SIZE, &expected);
    if (size != expected) return fail(r, PREL_PAYLOAD_SIZE_MISMATCH, "a payload's size doesn't match");
    hex_decode(r->sha256, STR(GET(p, "sha256")), 32);
    r->pinfo.name = STR(GET(p, "name"));
    r->pinfo.type = STR(GET(p, "type"));
    r->encrypted = enc != 0;
    prel_sha256_init(&r->stored_hash);
    prel_sha256_init(&r->plain_hash);
    if (r->encrypted) {
        uint_in(r, GET(p, "plain_size"), 1, MAX_SIZE, &r->pinfo.plain_size);
        uint_in(r, GET(enc, "chunk_size"), 1024, 1048576, &r->chunk_size);
        hex_decode(r->pinfo.plain_sha256, STR(GET(p, "plain_sha256")), 32);
        hex_decode(r->nonce_prefix, STR(GET(enc, "nonce_prefix")), 8);
        r->chunk = 0;
        r->chunk_count = (r->pinfo.plain_size + r->chunk_size - 1) / r->chunk_size;
    } else {
        r->pinfo.plain_size = size;
        memcpy(r->pinfo.plain_sha256, r->sha256, 32);
    }
    if (r->has_writer && r->writer.begin && r->writer.begin(r->writer.user, &r->pinfo) != 0)
        return fail(r, PREL_WRITER_FAILED, "the writer refused the payload");
    return !r->encrypted || start_chunk(r);
}

static bool emit(prel_reader *r, const uint8_t *plain, size_t len)
{
    prel_sha256_update(&r->plain_hash, plain, len);
    if (r->has_writer && r->writer.write && r->writer.write(r->writer.user, plain, len) != 0)
        return fail(r, PREL_WRITER_FAILED, "the writer failed");
    return true;
}

static bool payload_data(prel_reader *r, const uint8_t *data, size_t len)
{
    prel_sha256_update(&r->stored_hash, data, len);
    if (!r->encrypted) return emit(r, data, len);
    while (len) {
        if (r->ct_left) {
            size_t k = len < SCRATCH ? len : SCRATCH;
            if (k > r->ct_left) k = (size_t)r->ct_left;
            if (!prel_crypto_gcm_update(r->gcm, data, k, r->scratch)) return fail(r, PREL_WRITER_FAILED, "crypto backend");
            if (!emit(r, r->scratch, k)) return false;
            r->ct_left -= k;
            data += k;
            len -= k;
            continue;
        }
        size_t k = TAG - r->tag_fill < len ? TAG - r->tag_fill : len;
        memcpy(r->tag + r->tag_fill, data, k);
        r->tag_fill += k;
        data += k;
        len -= k;
        if (r->tag_fill < TAG) continue;
        if (!prel_crypto_gcm_finish(r->gcm, r->tag)) return fail(r, PREL_DECRYPT_FAILED, "a chunk doesn't authenticate");
        if (++r->chunk < r->chunk_count && !start_chunk(r)) return false;
    }
    return true;
}

static bool end_payload(prel_reader *r)
{
    uint8_t digest[32];
    prel_sha256_final(&r->stored_hash, digest);
    if (memcmp(digest, r->sha256, 32) != 0) return fail(r, PREL_PAYLOAD_HASH_MISMATCH, "a payload's sha256 doesn't match");
    if (r->encrypted) {
        if (r->chunk != r->chunk_count) return fail(r, PREL_DECRYPT_FAILED, "a payload ends inside a chunk");
        prel_sha256_final(&r->plain_hash, digest);
        if (memcmp(digest, r->pinfo.plain_sha256, 32) != 0)
            return fail(r, PREL_PLAIN_HASH_MISMATCH, "a payload's plain_sha256 doesn't match");
    }
    r->payloads_read++;
    r->payload = NEXT(r->payload);
    return true;
}

/* ---- step 1 and the archive -------------------------------------------------------------------- */

static bool octal(const uint8_t *f, size_t n, uint64_t *out)
{
    size_t end = n, start = 0;
    while (end && (f[end - 1] == 0 || f[end - 1] == ' ')) end--;
    while (start < end && f[start] == ' ') start++;
    if (start == end) return false;
    uint64_t v = 0;
    for (size_t i = start; i < end; i++) {
        if (f[i] < '0' || f[i] > '7') return false;
        v = v * 8 + (uint64_t)(f[i] - '0');
    }
    *out = v;
    return true;
}

static bool parse_header(prel_reader *r, char name[101], uint64_t *size)
{
    const uint8_t *h = r->block;
    uint64_t stored, sum = 8 * ' ';
    for (size_t i = 0; i < BLOCK; i++)
        if (i < 148 || i >= 156) sum += h[i];
    if (!octal(h + 148, 8, &stored) || stored != sum) return fail(r, PREL_RELEASE_MALFORMED, "entry header checksum");
    if (memcmp(h + 257, "ustar\0" "00", 8) != 0) return fail(r, PREL_RELEASE_MALFORMED, "entry header isn't POSIX ustar");
    if (h[156] != '0' && h[156] != 0) return fail(r, PREL_RELEASE_MALFORMED, "entry isn't a regular file");
    if (h[345] != 0) return fail(r, PREL_RELEASE_MALFORMED, "entry name uses the ustar prefix");
    size_t n = 0;
    while (n < 100 && h[n]) n++;
    memcpy(name, h, n);
    name[n] = 0;
    if (!entry_name_text(name, n)) return fail(r, PREL_RELEASE_MALFORMED, "bad entry name");
    if (!octal(h + 124, 12, size)) return fail(r, PREL_RELEASE_MALFORMED, "bad entry size");
    return true;
}

static void entry_done(prel_reader *r)
{
    if (r->entry == 1) {
        if (!check_manifest(r)) return;
        if (r->ctx->checks != PREL_CHECKS_INSTALLER) {
            succeed(r);
            return;
        }
    } else if (r->entry >= 2 && !end_payload(r)) {
        return;
    }
    r->entry++;
    r->state = r->pad_left ? S_PAD : S_HEADER;
}

static void on_header(prel_reader *r)
{
    static const uint8_t zero[BLOCK];
    r->block_fill = 0;
    if (memcmp(r->block, zero, BLOCK) == 0) {
        if (r->entry < 2) {
            fail(r, PREL_RELEASE_MALFORMED, "manifest.json and manifest.sig must come first");
        } else if (r->payloads_read < r->info.payload_count) {
            fail(r, PREL_RELEASE_MALFORMED, "a payload entry is missing");
        } else {
            r->state = S_END;
        }
        return;
    }
    char name[101];
    uint64_t size;
    if (!parse_header(r, name, &size)) return;
    if (r->entry == 0 && (strcmp(name, "manifest.json") != 0 || size > MANIFEST_MAX)) {
        fail(r, PREL_RELEASE_MALFORMED, "manifest.json must come first, within 65536 bytes");
        return;
    }
    if (r->entry == 1 && (strcmp(name, "manifest.sig") != 0 || size > SIGNATURE_MAX)) {
        fail(r, PREL_RELEASE_MALFORMED, "manifest.sig must come second, within 8192 bytes");
        return;
    }
    if (r->entry >= 2) {
        if (r->payloads_read >= r->info.payload_count) {
            fail(r, PREL_RELEASE_MALFORMED, "an entry follows the last payload");
            return;
        }
        if (!begin_payload(r, name, size)) return;
    }
    r->entry_left = size;
    r->pad_left = (size_t)((BLOCK - size % BLOCK) % BLOCK);
    r->state = S_DATA;
    if (size == 0) entry_done(r);
}

static size_t step(prel_reader *r, const uint8_t *data, size_t len)
{
    size_t k;
    switch (r->state) {
    case S_HEADER:
    case S_END:
        k = BLOCK - r->block_fill < len ? BLOCK - r->block_fill : len;
        memcpy(r->block + r->block_fill, data, k);
        r->block_fill += k;
        if (r->block_fill == BLOCK) {
            if (r->state == S_HEADER) {
                on_header(r);
            } else {
                static const uint8_t zero[BLOCK];
                r->block_fill = 0;
                if (memcmp(r->block, zero, BLOCK) != 0) fail(r, PREL_RELEASE_MALFORMED, "broken end-of-archive marker");
                r->state = S_TRAILER;
            }
        }
        return k;
    case S_DATA:
        k = r->entry_left < len ? (size_t)r->entry_left : len;
        if (r->entry == 0) {
            memcpy(r->manifest + r->manifest_len, data, k);
            r->manifest_len += k;
        } else if (r->entry == 1) {
            memcpy(r->sig + r->sig_len, data, k);
            r->sig_len += k;
        } else if (!payload_data(r, data, k)) {
            return k;
        }
        r->entry_left -= k;
        if (r->entry_left == 0) entry_done(r);
        return k;
    case S_PAD:
        k = r->pad_left < len ? r->pad_left : len;
        r->pad_left -= k;
        if (r->pad_left == 0) r->state = S_HEADER;
        return k;
    default: /* S_TRAILER */
        for (k = 0; k < len; k++)
            if (data[k]) {
                fail(r, PREL_RELEASE_MALFORMED, "data after the end of the archive");
                return k + 1;
            }
        return len;
    }
}

/* ---- public API -------------------------------------------------------------------------------- */

size_t prel_reader_size(void)
{
    return sizeof(prel_reader);
}

prel_reader *prel_reader_init(void *memory, size_t size, const prel_context *ctx, const prel_writer *writer)
{
    if (!memory || size < sizeof(prel_reader) || !ctx) return NULL;
    prel_reader *r = memory;
    memset(r, 0, offsetof(prel_reader, scratch));
    r->ctx = ctx;
    r->result = PREL_PENDING;
    r->detail = "";
    r->state = S_HEADER;
    if (writer && ctx->checks == PREL_CHECKS_INSTALLER) {
        r->writer = *writer;
        r->has_writer = true;
    }
    return r;
}

prel_result prel_reader_feed(prel_reader *r, const uint8_t *data, size_t len)
{
    while (len && r->result == PREL_PENDING) {
        size_t used = step(r, data, len);
        data += used;
        len -= used;
    }
    return r->result;
}

prel_result prel_reader_finish(prel_reader *r)
{
    if (r->result != PREL_PENDING) return r->result;
    if (r->state == S_TRAILER) {
        succeed(r);
    } else {
        fail(r, PREL_RELEASE_MALFORMED, "the file ends early");
    }
    return r->result;
}

const prel_manifest_info *prel_reader_manifest(const prel_reader *r)
{
    return r->have_info ? &r->info : NULL;
}

const char *prel_reader_detail(const prel_reader *r)
{
    return r->detail;
}

void prel_reader_release(prel_reader *r)
{
    if (!r) return;
    prel_crypto_gcm_free(r->gcm);
    r->gcm = NULL;
    wipe(r);
}
