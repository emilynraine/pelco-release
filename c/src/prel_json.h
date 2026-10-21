/* Strict JSON parsing as release-format.md section 3 requires. Internal to the library and its tests. */
#ifndef PREL_JSON_H
#define PREL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PREL_JSON_NULL = 1,
    PREL_JSON_FALSE,
    PREL_JSON_TRUE,
    PREL_JSON_NUMBER,
    PREL_JSON_STRING,
    PREL_JSON_ARRAY,
    PREL_JSON_OBJECT
};

/*
 * One value. Values are stored in document order, so a container's first child directly follows it.
 * Strings are unescaped in place and NUL-terminated, so the parsed buffer is no longer the original.
 */
typedef struct {
    uint8_t type;
    uint8_t is_integer;  /* a number written without fraction or exponent */
    uint16_t next;       /* next sibling, 0 if none */
    uint32_t start;      /* string: unescaped text; number: literal */
    uint32_t len;        /* string or literal length; container: number of children */
    uint32_t key_start;  /* object member: its unescaped name */
    uint32_t key_len;
} prel_json_node;

typedef struct {
    char *text;
    prel_json_node *nodes;
    size_t count;
} prel_json;

/* Parses buf in place. Fails on anything section 3 forbids, or over max_values / max_depth. */
bool prel_json_parse(prel_json *doc, uint8_t *buf, size_t len, prel_json_node *nodes,
                     size_t max_values, unsigned max_depth);

/* Index of an object's member, or 0 (the root can never be a member). */
size_t prel_json_get(const prel_json *doc, size_t object, const char *name);

/* Iterating children: first is 0 when there are none. */
size_t prel_json_first(const prel_json *doc, size_t container);
size_t prel_json_next(const prel_json *doc, size_t node);

bool prel_json_is(const prel_json *doc, size_t node, int type);
const char *prel_json_str(const prel_json *doc, size_t node);
size_t prel_json_strlen(const prel_json *doc, size_t node);
bool prel_json_str_eq(const prel_json *doc, size_t node, const char *s);

/* An integer literal from 0 to max; false for anything else. */
bool prel_json_uint(const prel_json *doc, size_t node, uint64_t max, uint64_t *out);

#endif
