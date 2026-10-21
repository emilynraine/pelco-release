/* SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869), backend-free. */
#ifndef PREL_SHA256_H
#define PREL_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length;
    uint8_t block[64];
    size_t fill;
} prel_sha256;

void prel_sha256_init(prel_sha256 *s);
void prel_sha256_update(prel_sha256 *s, const uint8_t *data, size_t len);
void prel_sha256_final(prel_sha256 *s, uint8_t out[32]);

/* HKDF-SHA256 with a 32-byte output. */
void prel_hkdf_sha256(uint8_t out[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                      size_t ikm_len, const uint8_t *info, size_t info_len);

#endif
