#include "prel_sha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16
             | (uint32_t)block[4 * i + 2] << 8 | (uint32_t)block[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

void prel_sha256_init(prel_sha256 *s)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->state, iv, sizeof iv);
    s->length = 0;
    s->fill = 0;
}

void prel_sha256_update(prel_sha256 *s, const uint8_t *data, size_t len)
{
    s->length += len;
    while (len) {
        size_t take = 64 - s->fill;
        if (take > len) take = len;
        memcpy(s->block + s->fill, data, take);
        s->fill += take;
        data += take;
        len -= take;
        if (s->fill == 64) {
            compress(s->state, s->block);
            s->fill = 0;
        }
    }
}

void prel_sha256_final(prel_sha256 *s, uint8_t out[32])
{
    uint64_t bits = s->length * 8;
    uint8_t pad = 0x80;
    prel_sha256_update(s, &pad, 1);
    pad = 0;
    while (s->fill != 56) prel_sha256_update(s, &pad, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56 - 8 * i));
    prel_sha256_update(s, len_be, 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->state[i];
    }
}

typedef struct {
    prel_sha256 inner, outer;
} hmac;

static void hmac_init(hmac *h, const uint8_t *key, size_t key_len)
{
    uint8_t k[64] = {0}, pad[64];
    if (key_len > 64) {
        prel_sha256 s;
        prel_sha256_init(&s);
        prel_sha256_update(&s, key, key_len);
        prel_sha256_final(&s, k);
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    prel_sha256_init(&h->inner);
    prel_sha256_update(&h->inner, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    prel_sha256_init(&h->outer);
    prel_sha256_update(&h->outer, pad, 64);
    memset(k, 0, sizeof k);
}

static void hmac_final(hmac *h, uint8_t out[32])
{
    uint8_t inner[32];
    prel_sha256_final(&h->inner, inner);
    prel_sha256_update(&h->outer, inner, 32);
    prel_sha256_final(&h->outer, out);
}

void prel_hkdf_sha256(uint8_t out[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                      size_t ikm_len, const uint8_t *info, size_t info_len)
{
    uint8_t prk[32];
    hmac h;
    hmac_init(&h, salt, salt_len);
    prel_sha256_update(&h.inner, ikm, ikm_len);
    hmac_final(&h, prk);
    hmac_init(&h, prk, sizeof prk);
    prel_sha256_update(&h.inner, info, info_len);
    uint8_t counter = 1;
    prel_sha256_update(&h.inner, &counter, 1);
    hmac_final(&h, out);
    memset(prk, 0, sizeof prk);
    memset(&h, 0, sizeof h);
}
