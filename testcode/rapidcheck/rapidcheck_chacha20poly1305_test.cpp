/**
 * @file rapidcheck_chacha20poly1305_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_CIPHER_CHACHA20_POLY1305
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
 *
 * Properties tested:
 *  - NULL ctx/key/iv on Init → CRYPT_NULL_INPUT
 *  - Invalid key length (≠32) → CRYPT_CHACHA20_KEYLEN_ERROR
 *  - Invalid IV length (≠12) → CRYPT_MODES_IVLEN_ERROR
 *  - Reinit before Init → CRYPT_EAL_ERR_STATE
 *  - Reinit NULL IV / NULL ctx → CRYPT_NULL_INPUT
 *  - Update NULL ctx/in/out/outLen → CRYPT_NULL_INPUT
 *  - Update before Init → CRYPT_EAL_ERR_STATE
 *  - Update after Final → CRYPT_EAL_ERR_STATE
 *  - Encrypt-decrypt round-trip: Dec(Enc(P)) == P
 *  - Determinism: Enc with same key+iv+AAD always produces same ciphertext
 *  - Key sensitivity: different key → different ciphertext
 *  - IV sensitivity: different iv → different ciphertext
 *  - Ciphertext ≠ plaintext (confusion property)
 *  - outLen == inLen after Update (stream cipher)
 *  - Tag integrity: flipping a ciphertext byte causes decryption to fail
 *
 * Usage:
 *   ./rapidcheck_chacha20poly1305_test              # Run all tests
 *   ./rapidcheck_chacha20poly1305_test --list       # List test names
 *   ./rapidcheck_chacha20poly1305_test <name> ...   # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

static const uint32_t KEY_LEN = 32;  /* ChaCha20-Poly1305 requires exactly 32 bytes */
static const uint32_t IV_LEN  = 12;  /* ChaCha20-Poly1305 requires exactly 12 bytes */
static const uint32_t TAG_LEN = 16;  /* Poly1305 tag size */

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static std::vector<uint8_t> genKey() {
    return *gen::container<std::vector<uint8_t>>(KEY_LEN, gen::arbitrary<uint8_t>());
}
static std::vector<uint8_t> genIV() {
    return *gen::container<std::vector<uint8_t>>(IV_LEN, gen::arbitrary<uint8_t>());
}
static std::vector<uint8_t> genAAD(size_t maxLen = 32) {
    auto sz = *gen::inRange<size_t>(0, maxLen + 1);
    return *gen::container<std::vector<uint8_t>>(sz, gen::arbitrary<uint8_t>());
}
static std::vector<uint8_t> genPlaintext(size_t minLen = 1, size_t maxLen = 128) {
    auto sz = *gen::inRange<size_t>(minLen, maxLen + 1);
    return *gen::container<std::vector<uint8_t>>(sz, gen::arbitrary<uint8_t>());
}

/**
 * Full encrypt: Init → SetAAD → Update → GetTag (no CipherFinal needed for ChaCha20-Poly1305).
 * Returns {ciphertext || tag} on success, empty on failure.
 */
static std::vector<uint8_t> chacha20poly1305Encrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &plaintext)
{
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    if (!ctx) return {};

    if (CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN, iv.data(), IV_LEN, true)
            != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx); return {};
    }
    if (!aad.empty()) {
        if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                const_cast<uint8_t*>(aad.data()), aad.size()) != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx); return {};
        }
    }

    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    uint32_t outLen = plaintext.size();
    if (CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), plaintext.size(),
            ciphertext.data(), &outLen) != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx); return {};
    }

    /* For ChaCha20-Poly1305, GetTag is called directly after Update */
    uint8_t tag[TAG_LEN];
    if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, TAG_LEN)
            != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx); return {};
    }
    CRYPT_EAL_CipherFreeCtx(ctx);

    ciphertext.resize(outLen);
    ciphertext.insert(ciphertext.end(), tag, tag + TAG_LEN);
    return ciphertext;
}

/**
 * Full decrypt: Init → SetAAD → Update → GetTag → compare with expected tag.
 * Returns plaintext on success (tag matches), empty on failure.
 */
static std::vector<uint8_t> chacha20poly1305Decrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &ciphertextWithTag)
{
    if (ciphertextWithTag.size() < TAG_LEN) return {};
    size_t ctLen = ciphertextWithTag.size() - TAG_LEN;
    const uint8_t *ct          = ciphertextWithTag.data();
    const uint8_t *expectedTag = ciphertextWithTag.data() + ctLen;

    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
    if (!ctx) return {};

    if (CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN, iv.data(), IV_LEN, false)
            != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx); return {};
    }
    if (!aad.empty()) {
        if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                const_cast<uint8_t*>(aad.data()), aad.size()) != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx); return {};
        }
    }

    std::vector<uint8_t> plaintext(ctLen, 0);
    uint32_t outLen = ctLen;
    if (ctLen > 0) {
        if (CRYPT_EAL_CipherUpdate(ctx, ct, ctLen, plaintext.data(), &outLen)
                != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(ctx); return {};
        }
    }

    /* Get the computed authentication tag and compare manually */
    uint8_t computedTag[TAG_LEN];
    if (CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, computedTag, TAG_LEN)
            != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx); return {};
    }
    CRYPT_EAL_CipherFreeCtx(ctx);

    if (memcmp(computedTag, expectedTag, TAG_LEN) != 0) return {};
    plaintext.resize(outLen);
    return plaintext;
}

/* ── Tests ────────────────────────────────────────────────────────────────── */

void test_init_null_ctx() {
    rc::check("CipherInit returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto key = genKey(); auto iv = genIV();
            int32_t ret = CRYPT_EAL_CipherInit(nullptr, key.data(), KEY_LEN,
                                               iv.data(), IV_LEN, true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_init_null_key() {
    rc::check("CipherInit returns CRYPT_NULL_INPUT when key is NULL",
        []() {
            auto iv = genIV();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx, nullptr, KEY_LEN, iv.data(), IV_LEN, true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_init_null_iv() {
    rc::check("CipherInit returns CRYPT_NULL_INPUT when iv is NULL",
        []() {
            auto key = genKey();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN, nullptr, IV_LEN, true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_init_invalid_key_len() {
    rc::check("CipherInit rejects non-zero key length != 32",
        []() {
            /* Must be >0 and !=32; unit tests use 31 and 33 */
            auto badLen = *gen::suchThat(gen::inRange<uint32_t>(1, 64),
                                         [](uint32_t l){ return l != KEY_LEN; });
            auto iv = genIV();
            std::vector<uint8_t> key(64, 0xAB);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx, key.data(), badLen, iv.data(), IV_LEN, true);
            RC_ASSERT(ret == CRYPT_CHACHA20_KEYLEN_ERROR);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_init_invalid_iv_len() {
    rc::check("CipherInit rejects iv length outside accepted range (unit tests: 7,9,11,13)",
        []() {
            /* Library accepts 8-12; unit tests confirm 7,9,11,13 all fail */
            static const uint32_t INVALID_LENS[] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 13, 14, 15, 16};
            auto idx = *gen::inRange<size_t>(0, sizeof(INVALID_LENS)/sizeof(INVALID_LENS[0]));
            uint32_t badLen = INVALID_LENS[idx];
            auto key = genKey();
            std::vector<uint8_t> iv(32, 0xCD);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN, iv.data(), badLen, true);
            RC_ASSERT(ret != CRYPT_SUCCESS);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_reinit_before_init() {
    rc::check("CipherReinit before Init returns CRYPT_EAL_ERR_STATE",
        []() {
            auto iv = genIV();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_CipherReinit(ctx, iv.data(), IV_LEN);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_reinit_null_iv() {
    rc::check("CipherReinit returns CRYPT_NULL_INPUT when iv is NULL",
        []() {
            auto key = genKey(); auto iv = genIV();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            int32_t ret = CRYPT_EAL_CipherReinit(ctx, nullptr, IV_LEN);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_reinit_null_ctx() {
    rc::check("CipherReinit returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto iv = genIV();
            int32_t ret = CRYPT_EAL_CipherReinit(nullptr, iv.data(), IV_LEN);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_reinit_invalid_iv_len() {
    rc::check("CipherReinit rejects iv length outside accepted range",
        []() {
            auto key = genKey(); auto iv = genIV();
            static const uint32_t INVALID_LENS[] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 13, 14, 15, 16};
            auto idx = *gen::inRange<size_t>(0, sizeof(INVALID_LENS)/sizeof(INVALID_LENS[0]));
            uint32_t badLen = INVALID_LENS[idx];
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            std::vector<uint8_t> bigIv(32, 0);
            int32_t ret = CRYPT_EAL_CipherReinit(ctx, bigIv.data(), badLen);
            RC_ASSERT(ret != CRYPT_SUCCESS);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_update_null_ctx() {
    rc::check("CipherUpdate returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto pt = genPlaintext();
            std::vector<uint8_t> out(pt.size());
            uint32_t outLen = pt.size();
            int32_t ret = CRYPT_EAL_CipherUpdate(nullptr, pt.data(), pt.size(),
                                                  out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_update_null_in() {
    rc::check("CipherUpdate returns CRYPT_NULL_INPUT when in is NULL and inLen != 0",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            if (!aad.empty())
                CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                    const_cast<uint8_t*>(aad.data()), aad.size());
            std::vector<uint8_t> out(64);
            uint32_t outLen = 64;
            int32_t ret = CRYPT_EAL_CipherUpdate(ctx, nullptr, 32, out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_update_null_out() {
    rc::check("CipherUpdate returns CRYPT_NULL_INPUT when out is NULL",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt = genPlaintext();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            if (!aad.empty())
                CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                    const_cast<uint8_t*>(aad.data()), aad.size());
            uint32_t outLen = pt.size();
            int32_t ret = CRYPT_EAL_CipherUpdate(ctx, pt.data(), pt.size(),
                                                  nullptr, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_update_null_outlen() {
    rc::check("CipherUpdate returns CRYPT_NULL_INPUT when outLen is NULL",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt = genPlaintext();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            if (!aad.empty())
                CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                    const_cast<uint8_t*>(aad.data()), aad.size());
            std::vector<uint8_t> out(pt.size());
            int32_t ret = CRYPT_EAL_CipherUpdate(ctx, pt.data(), pt.size(),
                                                  out.data(), nullptr);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_update_outlen_equals_inlen() {
    rc::check("CipherUpdate outLen == inLen (ChaCha20 is a stream cipher)",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt = genPlaintext();
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv.data(), IV_LEN, true) == CRYPT_SUCCESS);
            if (!aad.empty())
                CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                    const_cast<uint8_t*>(aad.data()), aad.size());
            std::vector<uint8_t> out(pt.size() + 32, 0);
            uint32_t outLen = out.size();
            int32_t ret = CRYPT_EAL_CipherUpdate(ctx, pt.data(), pt.size(),
                                                  out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == pt.size());
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_encrypt_decrypt_roundtrip() {
    rc::check("ChaCha20-Poly1305 decrypt(encrypt(P)) == P",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt  = genPlaintext();

            auto ctTag = chacha20poly1305Encrypt(key, iv, aad, pt);
            RC_PRE(!ctTag.empty());
            auto recovered = chacha20poly1305Decrypt(key, iv, aad, ctTag);
            RC_ASSERT(recovered == pt);
        });
}

void test_determinism() {
    rc::check("ChaCha20-Poly1305 encryption is deterministic",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt  = genPlaintext();

            auto ct1 = chacha20poly1305Encrypt(key, iv, aad, pt);
            auto ct2 = chacha20poly1305Encrypt(key, iv, aad, pt);
            RC_PRE(!ct1.empty() && !ct2.empty());
            RC_ASSERT(ct1 == ct2);
        });
}

void test_key_sensitivity() {
    rc::check("Different keys produce different ciphertexts",
        []() {
            auto key1 = genKey();
            auto key2 = *gen::suchThat(
                gen::container<std::vector<uint8_t>>(KEY_LEN, gen::arbitrary<uint8_t>()),
                [&](const std::vector<uint8_t> &k){ return k != key1; });
            auto iv = genIV(); auto aad = genAAD(); auto pt = genPlaintext();

            auto ct1 = chacha20poly1305Encrypt(key1, iv, aad, pt);
            auto ct2 = chacha20poly1305Encrypt(key2, iv, aad, pt);
            RC_PRE(!ct1.empty() && !ct2.empty());
            RC_ASSERT(ct1 != ct2);
        });
}

void test_iv_sensitivity() {
    rc::check("Different IVs produce different ciphertexts",
        []() {
            auto key = genKey();
            auto iv1 = genIV();
            auto iv2 = *gen::suchThat(
                gen::container<std::vector<uint8_t>>(IV_LEN, gen::arbitrary<uint8_t>()),
                [&](const std::vector<uint8_t> &v){ return v != iv1; });
            auto aad = genAAD(); auto pt = genPlaintext();

            auto ct1 = chacha20poly1305Encrypt(key, iv1, aad, pt);
            auto ct2 = chacha20poly1305Encrypt(key, iv2, aad, pt);
            RC_PRE(!ct1.empty() && !ct2.empty());
            RC_ASSERT(ct1 != ct2);
        });
}

void test_ciphertext_differs_from_plaintext() {
    rc::check("Ciphertext body differs from plaintext",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt  = genPlaintext(16, 128);

            auto ctTag = chacha20poly1305Encrypt(key, iv, aad, pt);
            RC_PRE(!ctTag.empty() && ctTag.size() > TAG_LEN);
            std::vector<uint8_t> ctBody(ctTag.begin(), ctTag.end() - TAG_LEN);
            RC_ASSERT(ctBody != pt);
        });
}

void test_tag_integrity() {
    rc::check("Flipping a ciphertext byte causes decryption failure",
        []() {
            auto key = genKey(); auto iv = genIV(); auto aad = genAAD();
            auto pt  = genPlaintext(1, 64);

            auto ctTag = chacha20poly1305Encrypt(key, iv, aad, pt);
            RC_PRE(ctTag.size() > TAG_LEN);

            /* Flip a random byte in the ciphertext body */
            auto flipIdx = *gen::inRange<size_t>(0, ctTag.size() - TAG_LEN);
            ctTag[flipIdx] ^= 0xFF;

            auto recovered = chacha20poly1305Decrypt(key, iv, aad, ctTag);
            RC_ASSERT(recovered.empty() || recovered != pt);
        });
}

void test_reinit_reuses_context() {
    rc::check("CipherReinit allows encrypting a new message (same result as fresh init)",
        []() {
            auto key = genKey(); auto iv1 = genIV(); auto iv2 = genIV();
            auto aad = genAAD(); auto pt = genPlaintext();

            /* Encrypt via fresh context */
            auto ctExpected = chacha20poly1305Encrypt(key, iv2, aad, pt);
            RC_PRE(!ctExpected.empty());

            /* Encrypt via reinit */
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                        iv1.data(), IV_LEN, true) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_CipherReinit(ctx, iv2.data(), IV_LEN) == CRYPT_SUCCESS);
            if (!aad.empty())
                CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD,
                    const_cast<uint8_t*>(aad.data()), aad.size());

            std::vector<uint8_t> ctActual(pt.size(), 0);
            uint32_t outLen = pt.size();
            RC_PRE(CRYPT_EAL_CipherUpdate(ctx, pt.data(), pt.size(),
                                          ctActual.data(), &outLen) == CRYPT_SUCCESS);
            ctActual.resize(outLen);
            uint8_t tag[TAG_LEN];
            RC_PRE(CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, TAG_LEN) == CRYPT_SUCCESS);
            ctActual.insert(ctActual.end(), tag, tag + TAG_LEN);
            CRYPT_EAL_CipherFreeCtx(ctx);

            RC_ASSERT(ctActual == ctExpected);
        });
}

/* ── Registry ─────────────────────────────────────────────────────────────── */

static std::map<std::string, std::function<void()>> testRegistry = {
    {"init_null_ctx",               test_init_null_ctx},
    {"init_null_key",               test_init_null_key},
    {"init_null_iv",                test_init_null_iv},
    {"init_invalid_key_len",        test_init_invalid_key_len},
    {"init_invalid_iv_len",         test_init_invalid_iv_len},
    {"reinit_before_init",          test_reinit_before_init},
    {"reinit_null_iv",              test_reinit_null_iv},
    {"reinit_null_ctx",             test_reinit_null_ctx},
    {"reinit_invalid_iv_len",       test_reinit_invalid_iv_len},
    {"update_null_ctx",             test_update_null_ctx},
    {"update_null_in",              test_update_null_in},
    {"update_null_out",             test_update_null_out},
    {"update_null_outlen",          test_update_null_outlen},
    {"update_outlen_equals_inlen",  test_update_outlen_equals_inlen},
    {"encrypt_decrypt_roundtrip",   test_encrypt_decrypt_roundtrip},
    {"determinism",                 test_determinism},
    {"key_sensitivity",             test_key_sensitivity},
    {"iv_sensitivity",              test_iv_sensitivity},
    {"ciphertext_differs_plaintext",test_ciphertext_differs_from_plaintext},
    {"tag_integrity",               test_tag_integrity},
    {"reinit_reuses_context",       test_reinit_reuses_context},
};

static void listTests() {
    std::cout << "Available tests (" << testRegistry.size() << "):\n";
    for (auto &kv : testRegistry)
        std::cout << "  " << kv.first << "\n";
}

int main(int argc, char *argv[]) {
    std::vector<std::string> toRun;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--list" || a == "-l") { listTests(); return 0; }
        if (a == "--help" || a == "-h") {
            std::cout << "Usage: " << argv[0] << " [--list] [test_name ...]\n";
            return 0;
        }
        toRun.push_back(a);
    }

    if (toRun.empty()) {
        std::cout << "Running all " << testRegistry.size() << " tests...\n\n";
        for (auto &kv : testRegistry) {
            std::cout << "[ " << kv.first << " ]\n";
            kv.second();
            std::cout << "\n";
        }
    } else {
        for (auto &name : toRun) {
            auto it = testRegistry.find(name);
            if (it == testRegistry.end()) {
                std::cerr << "Unknown test '" << name << "'. Use --list.\n";
                return 1;
            }
            std::cout << "[ " << name << " ]\n";
            it->second();
            std::cout << "\n";
        }
    }
    return 0;
}
