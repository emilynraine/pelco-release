/* The crypto backend on OpenSSL 1.1.1 or later. */
#include "prel_crypto.h"

#include <limits.h>
#include <string.h>

#include <openssl/evp.h>

int prel_crypto_ed25519_verify(const uint8_t public_key[32], const uint8_t *msg, size_t len,
                               const uint8_t sig[64])
{
    int ok = 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1)
        ok = EVP_DigestVerify(ctx, sig, 64, msg, len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

int prel_crypto_x25519(uint8_t shared[32], const uint8_t private_key[32], const uint8_t peer[32])
{
    static const uint8_t zero[32] = {0};
    int ok = 0;
    size_t len = 32;
    EVP_PKEY *own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    EVP_PKEY *other = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *ctx = own ? EVP_PKEY_CTX_new(own, NULL) : NULL;
    if (ctx && other && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, other) == 1
        && EVP_PKEY_derive(ctx, shared, &len) == 1 && len == 32)
        ok = memcmp(shared, zero, 32) != 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(other);
    EVP_PKEY_free(own);
    return ok;
}

int prel_crypto_x25519_public(uint8_t public_key[32], const uint8_t private_key[32])
{
    size_t len = 32;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    int ok = key && EVP_PKEY_get_raw_public_key(key, public_key, &len) == 1 && len == 32;
    EVP_PKEY_free(key);
    return ok;
}

int prel_crypto_aes256_unwrap(uint8_t out[32], const uint8_t kek[32], const uint8_t wrapped[40])
{
    uint8_t buf[48];
    int len = 0, final_len = 0, ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL) == 1
          && EVP_DecryptUpdate(ctx, buf, &len, wrapped, 40) == 1
          && EVP_DecryptFinal_ex(ctx, buf + len, &final_len) == 1 && len + final_len == 32;
    }
    if (ok) memcpy(out, buf, 32);
    memset(buf, 0, sizeof buf);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

struct prel_gcm {
    EVP_CIPHER_CTX *ctx;
};

prel_gcm *prel_crypto_gcm_new(void)
{
    prel_gcm *gcm = OPENSSL_zalloc(sizeof *gcm);
    if (gcm && !(gcm->ctx = EVP_CIPHER_CTX_new())) {
        OPENSSL_free(gcm);
        return NULL;
    }
    return gcm;
}

int prel_crypto_gcm_start(prel_gcm *gcm, const uint8_t key[32], const uint8_t nonce[12], uint8_t aad)
{
    int len;
    return EVP_DecryptInit_ex(gcm->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(gcm->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
        && EVP_DecryptInit_ex(gcm->ctx, NULL, NULL, key, nonce) == 1
        && EVP_DecryptUpdate(gcm->ctx, NULL, &len, &aad, 1) == 1;
}

int prel_crypto_gcm_update(prel_gcm *gcm, const uint8_t *in, size_t len, uint8_t *out)
{
    int out_len;
    return len <= INT_MAX && EVP_DecryptUpdate(gcm->ctx, out, &out_len, in, (int)len) == 1
        && (size_t)out_len == len;
}

int prel_crypto_gcm_finish(prel_gcm *gcm, const uint8_t tag[16])
{
    uint8_t rest[16];
    int len;
    return EVP_CIPHER_CTX_ctrl(gcm->ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1
        && EVP_DecryptFinal_ex(gcm->ctx, rest, &len) == 1;
}

void prel_crypto_gcm_free(prel_gcm *gcm)
{
    if (!gcm) return;
    EVP_CIPHER_CTX_free(gcm->ctx);
    OPENSSL_free(gcm);
}
