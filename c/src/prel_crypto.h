/*
 * What a crypto backend provides. The library links exactly one backend: prel_crypto_openssl.c for
 * Linux hosts and controllers. Another (mbedTLS plus an Ed25519 implementation, for ESP32) implements
 * these same functions. Every function returns 1 on success and 0 on failure.
 */
#ifndef PREL_CRYPTO_H
#define PREL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int prel_crypto_ed25519_verify(const uint8_t public_key[32], const uint8_t *msg, size_t len,
                               const uint8_t sig[64]);

/* Fails on an all-zero shared secret. */
int prel_crypto_x25519(uint8_t shared[32], const uint8_t private_key[32], const uint8_t peer[32]);
int prel_crypto_x25519_public(uint8_t public_key[32], const uint8_t private_key[32]);

/* AES-256 key unwrap (RFC 3394) of a 32-byte key. */
int prel_crypto_aes256_unwrap(uint8_t out[32], const uint8_t kek[32], const uint8_t wrapped[40]);

/* AES-256-GCM decryption of one chunk: start, update any number of times, then finish with the tag. */
typedef struct prel_gcm prel_gcm;
prel_gcm *prel_crypto_gcm_new(void);
int prel_crypto_gcm_start(prel_gcm *gcm, const uint8_t key[32], const uint8_t nonce[12], uint8_t aad);
int prel_crypto_gcm_update(prel_gcm *gcm, const uint8_t *in, size_t len, uint8_t *out);
int prel_crypto_gcm_finish(prel_gcm *gcm, const uint8_t tag[16]);
void prel_crypto_gcm_free(prel_gcm *gcm);

#endif
