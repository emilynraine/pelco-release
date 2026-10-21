#include "prel_json.h"

#include <string.h>

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t pos;
    prel_json_node *nodes;
    size_t count;
    size_t max_values;
    unsigned max_depth;
} parser;

/* Strict UTF-8, as Python's decoder: no overlongs, no surrogates, nothing above U+10FFFF. */
static bool valid_utf8(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        size_t extra;
        uint8_t lo = 0x80, hi = 0xBF;
        if (c < 0x80) {
            i++;
            continue;
        } else if (c >= 0xC2 && c <= 0xDF) {
            extra = 1;
        } else if (c >= 0xE0 && c <= 0xEF) {
            extra = 2;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            extra = 3;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            return false;
        }
        if (n - i <= extra) return false;
        if (s[i + 1] < lo || s[i + 1] > hi) return false;
        for (size_t k = 2; k <= extra; k++)
            if (s[i + k] < 0x80 || s[i + k] > 0xBF) return false;
        i += extra + 1;
    }
    return true;
}

static void skip_ws(parser *p)
{
    while (p->pos < p->len) {
        uint8_t c = p->buf[p->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
        p->pos++;
    }
}

static bool peek(parser *p, uint8_t c)
{
    return p->pos < p->len && p->buf[p->pos] == c;
}

static int hex_digit(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool read_hex4(parser *p, size_t at, uint32_t *out)
{
    if (at + 4 > p->len) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < 4; i++) {
        int d = hex_digit(p->buf[at + i]);
        if (d < 0) return false;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v;
    return true;
}

/* Unescapes the string at p->pos (just after its opening quote) in place. */
static bool parse_string(parser *p, uint32_t *start, uint32_t *len)
{
    size_t out = p->pos;
    *start = (uint32_t)out;
    for (;;) {
        if (p->pos >= p->len) return false;
        uint8_t c = p->buf[p->pos];
        if (c == '"') {
            *len = (uint32_t)(out - *start);
            p->buf[out] = 0; /* out <= pos: overwrites only consumed text */
            p->pos++;
            return true;
        }
        if (c < 0x20) return false;
        if (c != '\\') {
            p->buf[out++] = c;
            p->pos++;
            continue;
        }
        if (p->pos + 1 >= p->len) return false;
        uint8_t e = p->buf[p->pos + 1];
        p->pos += 2;
        switch (e) {
        case '"': p->buf[out++] = '"'; continue;
        case '\\': p->buf[out++] = '\\'; continue;
        case '/': p->buf[out++] = '/'; continue;
        case 'b': p->buf[out++] = '\b'; continue;
        case 'f': p->buf[out++] = '\f'; continue;
        case 'n': p->buf[out++] = '\n'; continue;
        case 'r': p->buf[out++] = '\r'; continue;
        case 't': p->buf[out++] = '\t'; continue;
        case 'u': break;
        default: return false;
        }
        uint32_t cp;
        if (!read_hex4(p, p->pos, &cp)) return false;
        p->pos += 4;
        if (cp >= 0xDC00 && cp <= 0xDFFF) return false; /* unpaired low surrogate */
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            uint32_t low;
            if (p->pos + 6 > p->len || p->buf[p->pos] != '\\' || p->buf[p->pos + 1] != 'u'
                || !read_hex4(p, p->pos + 2, &low) || low < 0xDC00 || low > 0xDFFF)
                return false; /* unpaired high surrogate */
            p->pos += 6;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
        }
        if (cp < 0x80) {
            p->buf[out++] = (uint8_t)cp;
        } else if (cp < 0x800) {
            p->buf[out++] = (uint8_t)(0xC0 | (cp >> 6));
            p->buf[out++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            p->buf[out++] = (uint8_t)(0xE0 | (cp >> 12));
            p->buf[out++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            p->buf[out++] = (uint8_t)(0x80 | (cp & 0x3F));
        } else {
            p->buf[out++] = (uint8_t)(0xF0 | (cp >> 18));
            p->buf[out++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
            p->buf[out++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            p->buf[out++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
    }
}

static bool is_digit(parser *p)
{
    return p->pos < p->len && p->buf[p->pos] >= '0' && p->buf[p->pos] <= '9';
}

static bool parse_number(parser *p, prel_json_node *n)
{
    size_t start = p->pos;
    bool integer = true;
    if (peek(p, '-')) p->pos++;
    if (peek(p, '0')) {
        p->pos++;
    } else if (is_digit(p)) {
        while (is_digit(p)) p->pos++;
    } else {
        return false;
    }
    if (peek(p, '.')) {
        integer = false;
        p->pos++;
        if (!is_digit(p)) return false;
        while (is_digit(p)) p->pos++;
    }
    if (peek(p, 'e') || peek(p, 'E')) {
        integer = false;
        p->pos++;
        if (peek(p, '+') || peek(p, '-')) p->pos++;
        if (!is_digit(p)) return false;
        while (is_digit(p)) p->pos++;
    }
    n->type = PREL_JSON_NUMBER;
    n->is_integer = integer;
    n->start = (uint32_t)start;
    n->len = (uint32_t)(p->pos - start);
    return true;
}

static bool literal(parser *p, const char *word)
{
    size_t n = strlen(word);
    if (p->len - p->pos < n || memcmp(p->buf + p->pos, word, n) != 0) return false;
    p->pos += n;
    return true;
}

static bool keys_unique(parser *p, size_t object)
{
    for (size_t a = object + 1; a; a = p->nodes[a].next) {
        for (size_t b = p->nodes[a].next; b; b = p->nodes[b].next) {
            if (p->nodes[a].key_len == p->nodes[b].key_len
                && memcmp(p->buf + p->nodes[a].key_start, p->buf + p->nodes[b].key_start,
                          p->nodes[a].key_len) == 0)
                return false;
        }
    }
    return true;
}

static bool parse_value(parser *p, unsigned depth, uint32_t key_start, uint32_t key_len);

static bool parse_container(parser *p, size_t self, unsigned depth, bool object)
{
    uint8_t close = object ? '}' : ']';
    size_t previous = 0;
    p->pos++;
    skip_ws(p);
    if (peek(p, close)) {
        p->pos++;
        return true;
    }
    for (;;) {
        uint32_t key_start = 0, key_len = 0;
        if (object) {
            if (!peek(p, '"')) return false;
            p->pos++;
            if (!parse_string(p, &key_start, &key_len)) return false;
            skip_ws(p);
            if (!peek(p, ':')) return false;
            p->pos++;
            skip_ws(p);
        }
        size_t child = p->count;
        if (!parse_value(p, depth + 1, key_start, key_len)) return false;
        if (previous) p->nodes[previous].next = (uint16_t)child;
        previous = child;
        p->nodes[self].len++;
        skip_ws(p);
        if (peek(p, ',')) {
            p->pos++;
            skip_ws(p);
            continue;
        }
        if (!peek(p, close)) return false;
        p->pos++;
        return !object || keys_unique(p, self);
    }
}

static bool parse_value(parser *p, unsigned depth, uint32_t key_start, uint32_t key_len)
{
    if (depth > p->max_depth || p->count >= p->max_values || p->pos >= p->len) return false;
    size_t self = p->count++;
    prel_json_node *n = &p->nodes[self];
    memset(n, 0, sizeof *n);
    n->key_start = key_start;
    n->key_len = key_len;
    switch (p->buf[p->pos]) {
    case '{':
        n->type = PREL_JSON_OBJECT;
        return parse_container(p, self, depth, true);
    case '[':
        n->type = PREL_JSON_ARRAY;
        return parse_container(p, self, depth, false);
    case '"': {
        uint32_t start, len;
        p->pos++;
        if (!parse_string(p, &start, &len)) return false;
        n = &p->nodes[self];
        n->type = PREL_JSON_STRING;
        n->start = start;
        n->len = len;
        return true;
    }
    case 't':
        n->type = PREL_JSON_TRUE;
        return literal(p, "true");
    case 'f':
        n->type = PREL_JSON_FALSE;
        return literal(p, "false");
    case 'n':
        n->type = PREL_JSON_NULL;
        return literal(p, "null");
    default:
        return parse_number(p, n);
    }
}

bool prel_json_parse(prel_json *doc, uint8_t *buf, size_t len, prel_json_node *nodes,
                     size_t max_values, unsigned max_depth)
{
    if (max_values > 65535) max_values = 65535; /* node links are 16-bit */
    if (len >= UINT32_MAX || !valid_utf8(buf, len)) return false;
    if (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) return false;
    parser p = {buf, len, 0, nodes, 0, max_values, max_depth};
    skip_ws(&p);
    if (!parse_value(&p, 1, 0, 0)) return false;
    skip_ws(&p);
    if (p.pos != len) return false;
    doc->text = (char *)buf;
    doc->nodes = nodes;
    doc->count = p.count;
    return true;
}

size_t prel_json_first(const prel_json *doc, size_t container)
{
    const prel_json_node *n = &doc->nodes[container];
    if ((n->type != PREL_JSON_ARRAY && n->type != PREL_JSON_OBJECT) || n->len == 0) return 0;
    return container + 1;
}

size_t prel_json_next(const prel_json *doc, size_t node)
{
    return doc->nodes[node].next;
}

size_t prel_json_get(const prel_json *doc, size_t object, const char *name)
{
    if (doc->nodes[object].type != PREL_JSON_OBJECT) return 0;
    size_t len = strlen(name);
    for (size_t c = prel_json_first(doc, object); c; c = prel_json_next(doc, c)) {
        const prel_json_node *n = &doc->nodes[c];
        if (n->key_len == len && memcmp(doc->text + n->key_start, name, len) == 0) return c;
    }
    return 0;
}

bool prel_json_is(const prel_json *doc, size_t node, int type)
{
    return node && doc->nodes[node].type == type;
}

const char *prel_json_str(const prel_json *doc, size_t node)
{
    return doc->text + doc->nodes[node].start;
}

size_t prel_json_strlen(const prel_json *doc, size_t node)
{
    return doc->nodes[node].len;
}

bool prel_json_str_eq(const prel_json *doc, size_t node, const char *s)
{
    size_t len = strlen(s);
    return prel_json_is(doc, node, PREL_JSON_STRING) && doc->nodes[node].len == len
        && memcmp(doc->text + doc->nodes[node].start, s, len) == 0;
}

bool prel_json_uint(const prel_json *doc, size_t node, uint64_t max, uint64_t *out)
{
    if (!prel_json_is(doc, node, PREL_JSON_NUMBER) || !doc->nodes[node].is_integer) return false;
    const char *s = doc->text + doc->nodes[node].start;
    size_t len = doc->nodes[node].len;
    if (s[0] == '-') return len == 2 && s[1] == '0' && (*out = 0, true);
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t d = (uint64_t)(s[i] - '0');
        if (d > max || v > (max - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}
