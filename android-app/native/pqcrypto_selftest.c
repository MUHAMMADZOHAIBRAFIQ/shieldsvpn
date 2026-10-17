/*
 * On-device check of the packaged OpenSSL (libcrypto_pqvpn.so): runs every primitive pqvpn uses.
 *
 *   build:  see build-selftest.sh (NDK clang, one binary per ABI, linked against the packaged library)
 *   run:    adb push pqcrypto_selftest-<abi> libcrypto_pqvpn.so /data/local/tmp/
 *           adb shell 'cd /data/local/tmp && LD_LIBRARY_PATH=. ./pqcrypto_selftest-<abi>'
 *
 * Exit status 0 = every check passed.
 */
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, what) do { if (cond) printf("  ok    %s\n", what); else { printf("  FAIL  %s\n", what); failures++; } } while (0)

static EVP_PKEY *keygen(const char *alg) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (c && EVP_PKEY_keygen_init(c) > 0) EVP_PKEY_generate(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static void kem(const char *alg) {
    EVP_PKEY *k = keygen(alg);
    unsigned char ct[2048], ss1[64], ss2[64];
    size_t ctlen = sizeof ct, l1 = sizeof ss1, l2 = sizeof ss2;
    EVP_PKEY_CTX *e = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    int ok = k && e && EVP_PKEY_encapsulate_init(e, NULL) > 0 && EVP_PKEY_encapsulate(e, ct, &ctlen, ss1, &l1) > 0;
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    ok = ok && d && EVP_PKEY_decapsulate_init(d, NULL) > 0 && EVP_PKEY_decapsulate(d, ss2, &l2, ct, ctlen) > 0;
    char what[96];
    snprintf(what, sizeof what, "%s encapsulate/decapsulate (ct %zu B, ss %zu B)", alg, ctlen, l1);
    CHECK(ok && l1 == l2 && memcmp(ss1, ss2, l1) == 0, what);
    EVP_PKEY_CTX_free(e); EVP_PKEY_CTX_free(d); EVP_PKEY_free(k);
}

static void ecdh(const char *alg) {
    EVP_PKEY *a = keygen(alg), *b = keygen(alg);
    unsigned char s1[64], s2[64];
    size_t l1 = sizeof s1, l2 = sizeof s2;
    EVP_PKEY_CTX *ca = EVP_PKEY_CTX_new_from_pkey(NULL, a, NULL), *cb = EVP_PKEY_CTX_new_from_pkey(NULL, b, NULL);
    int ok = a && b && ca && cb && EVP_PKEY_derive_init(ca) > 0 && EVP_PKEY_derive_set_peer_ex(ca, b, 1) > 0 &&
             EVP_PKEY_derive(ca, s1, &l1) > 0 && EVP_PKEY_derive_init(cb) > 0 &&
             EVP_PKEY_derive_set_peer_ex(cb, a, 1) > 0 && EVP_PKEY_derive(cb, s2, &l2) > 0;
    char what[64];
    snprintf(what, sizeof what, "%s key agreement", alg);
    CHECK(ok && l1 == l2 && memcmp(s1, s2, l1) == 0, what);
    EVP_PKEY_CTX_free(ca); EVP_PKEY_CTX_free(cb); EVP_PKEY_free(a); EVP_PKEY_free(b);
}

static void sig(const char *alg) {
    EVP_PKEY *k = keygen(alg);
    static const unsigned char msg[] = "pqvpn transcript hash", ctxs[] = "pqvpn1 initiator CertificateVerify";
    OSSL_PARAM p[2] = {OSSL_PARAM_construct_octet_string("context-string", (void *)ctxs, sizeof ctxs - 1),
                       OSSL_PARAM_construct_end()};
    unsigned char s[50000];
    size_t slen = sizeof s;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = k && m && EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, k, p) > 0 &&
             EVP_DigestSign(m, s, &slen, msg, sizeof msg) > 0;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    int good = ok && EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, k, p) > 0 &&
               EVP_DigestVerify(m, s, slen, msg, sizeof msg) == 1;
    EVP_MD_CTX_free(m);
    s[10] ^= 1;  /* a modified signature must be rejected */
    m = EVP_MD_CTX_new();
    int bad = EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, k, p) > 0 && EVP_DigestVerify(m, s, slen, msg, sizeof msg) == 1;
    EVP_MD_CTX_free(m);
    char what[96];
    snprintf(what, sizeof what, "%s sign/verify with context (sig %zu B), tamper rejected", alg, slen);
    CHECK(good && !bad, what);
    EVP_PKEY_free(k);
}

static void aead(const char *name) {
    unsigned char key[32] = {1}, nonce[12] = {2}, aad[16] = {3}, pt[64] = "inner IP packet", ct[80], out[80], tag[16];
    int n = 0, f = 0;
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, name, NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int ok = c && x && EVP_EncryptInit_ex2(x, c, key, nonce, NULL) > 0 && EVP_EncryptUpdate(x, NULL, &n, aad, sizeof aad) > 0 &&
             EVP_EncryptUpdate(x, ct, &n, pt, sizeof pt) > 0 && EVP_EncryptFinal_ex(x, ct + n, &f) > 0 &&
             EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, tag) > 0;
    EVP_CIPHER_CTX_free(x);
    x = EVP_CIPHER_CTX_new();
    ok = ok && EVP_DecryptInit_ex2(x, c, key, nonce, NULL) > 0 && EVP_DecryptUpdate(x, NULL, &n, aad, sizeof aad) > 0 &&
         EVP_DecryptUpdate(x, out, &n, ct, sizeof pt) > 0 && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, tag) > 0 &&
         EVP_DecryptFinal_ex(x, out + n, &f) == 1 && memcmp(out, pt, sizeof pt) == 0;
    EVP_CIPHER_CTX_free(x);
    tag[0] ^= 1;
    x = EVP_CIPHER_CTX_new();
    int forged = EVP_DecryptInit_ex2(x, c, key, nonce, NULL) > 0 && EVP_DecryptUpdate(x, NULL, &n, aad, sizeof aad) > 0 &&
                 EVP_DecryptUpdate(x, out, &n, ct, sizeof pt) > 0 && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, tag) > 0 &&
                 EVP_DecryptFinal_ex(x, out + n, &f) == 1;
    EVP_CIPHER_CTX_free(x);
    EVP_CIPHER_free(c);
    char what[64];
    snprintf(what, sizeof what, "%s seal/open, forged tag rejected", name);
    CHECK(ok && !forged, what);
}

int main(void) {
    printf("%s (version number 0x%08lx)\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version_num());
    CHECK(OpenSSL_version_num() >= 0x30500000L, "OpenSSL >= 3.5");
    kem("ML-KEM-768");
    kem("ML-KEM-1024");
    ecdh("X25519");
    sig("ML-DSA-65");
    sig("ML-DSA-87");
    sig("SLH-DSA-SHA2-128f");
    aead("ChaCha20-Poly1305");
    aead("AES-256-GCM");
    printf(failures ? "%d check(s) FAILED\n" : "all checks passed\n", failures);
    return failures != 0;
}
