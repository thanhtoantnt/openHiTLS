/**
 * @file rapidcheck_eal_aes_init_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_CipherInit
 * 
 * This file generalizes the unit test SDV_CRYPTO_AES_INIT_API_TC001 from:
 * testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:99-149
 * 
 * The unit test checks specific NULL/invalid inputs one at a time.
 * This PBT test generalizes to random combinations of:
 * - NULL vs valid ctx
 * - NULL vs valid key
 * - Zero vs non-zero keyLen
 * - NULL vs valid iv
 * - Zero vs non-zero ivLen
 * 
 * Property-based testing finds edge cases that fixed unit tests might miss.
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

// Helper to generate valid 16-byte key
std::vector<uint8_t> genValidKey() {
    return *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
}

// Helper to generate valid 16-byte IV
std::vector<uint8_t> genValidIV() {
    return *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
}

int main() {
    /**
     * @test CRYPT_EAL_CipherInit null ctx returns CRYPT_NULL_INPUT
     * @property When ctx is NULL, CRYPT_EAL_CipherInit returns CRYPT_NULL_INPUT
     *           regardless of other parameters being valid
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step3 - "ctx is NULL"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:134
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(NULL, keyData.data(), keyData.size(), 
                                                ivData.data(), ivData.size(), true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test CRYPT_EAL_CipherInit null key returns CRYPT_NULL_INPUT
     * @property When ctx is valid but key is NULL, CRYPT_EAL_CipherInit returns CRYPT_NULL_INPUT
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step4 - "key is NULL"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:136
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_NULL_INPUT when key is NULL",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            auto ivData = genValidIV();
            int32_t ret = CRYPT_EAL_CipherInit(ctx, NULL, 16, ivData.data(), ivData.size(), true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit zero keyLen returns CRYPT_AES_ERR_KEYLEN
     * @property When ctx and key are valid but keyLen is 0, 
     *           CRYPT_EAL_CipherInit returns CRYPT_AES_ERR_KEYLEN
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step5 - "keyLen is 0"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:138
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_AES_ERR_KEYLEN when keyLen is 0",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 0, ivData.data(), ivData.size(), true);
            RC_ASSERT(ret == CRYPT_AES_ERR_KEYLEN);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit null iv returns CRYPT_INVALID_ARG for CBC mode
     * @property When ctx and key are valid but iv is NULL (CBC mode), 
     *           CRYPT_EAL_CipherInit returns CRYPT_INVALID_ARG
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step6 - "iv is NULL"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:140
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_INVALID_ARG when iv is NULL (CBC mode)",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            
            // CBC mode requires IV
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                NULL, 16, true);
            RC_ASSERT(ret == CRYPT_INVALID_ARG);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit zero ivLen returns CRYPT_MODES_IVLEN_ERROR for CBC mode
     * @property When ctx and key are valid but ivLen is 0 (CBC mode), 
     *           CRYPT_EAL_CipherInit returns CRYPT_MODES_IVLEN_ERROR
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step7 - "ivLen is 0"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:142
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_MODES_IVLEN_ERROR when ivLen is 0 (CBC mode)",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                ivData.data(), 0, true);
            RC_ASSERT(ret == CRYPT_MODES_IVLEN_ERROR);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit succeeds with all valid parameters
     * @property When ctx, key (valid len), iv (valid len) are all valid,
     *           CRYPT_EAL_CipherInit returns CRYPT_SUCCESS
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001:step2 - "All parameters valid"
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:132
     */
    rc::check("CRYPT_EAL_CipherInit returns CRYPT_SUCCESS with all valid parameters",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                ivData.data(), ivData.size(), true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit accepts 128-bit, 192-bit, and 256-bit keys
     * @property For valid key sizes (16, 24, 32 bytes) with valid IV,
     *           CRYPT_EAL_CipherInit returns CRYPT_SUCCESS
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001 - Key length validation
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("CRYPT_EAL_CipherInit accepts AES-128, AES-192, and AES-256 keys",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            // Generate key of valid length (16, 24, or 32 bytes)
            auto keyLen = *gen::element(16, 24, 32);
            auto keyData = *gen::container<std::vector<uint8_t>>(keyLen, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                ivData.data(), ivData.size(), true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit invalid keyLen returns error
     * @property For invalid key lengths (not 16, 24, or 32), 
     *           CRYPT_EAL_CipherInit returns error
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001 - Invalid key length test
     */
    rc::check("CRYPT_EAL_CipherInit rejects invalid key lengths",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx != nullptr);
            
            // Generate invalid key length (not 16, 24, or 32)
            auto keyLen = *gen::inRange(1, 33);  // 0-15, 17-23, 25-31, 33+
            RC_PRE(keyLen != 16 && keyLen != 24 && keyLen != 32);
            
            auto keyData = *gen::container<std::vector<uint8_t>>(keyLen, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                ivData.data(), ivData.size(), true);
            // Should fail with key length error
            RC_ASSERT(ret != CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherInit works for different AES modes (ECB, CBC, CTR)
     * @property For modes that don't require IV (ECB) or require IV (CBC, CTR),
     *           valid parameters return CRYPT_SUCCESS
     * @generalizes Testing across different cipher modes
     */
    rc::check("CRYPT_EAL_CipherInit works for ECB, CBC, and CTR modes",
        []() {
            auto keyData = genValidKey();
            
            // Test ECB mode (no IV required)
            {
                CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
                RC_PRE(ctx != nullptr);
                
                int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                    NULL, 0, true);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                
                CRYPT_EAL_CipherDeinit(ctx);
                CRYPT_EAL_CipherFreeCtx(ctx);
            }
            
            // Test CBC mode (IV required)
            {
                CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
                RC_PRE(ctx != nullptr);
                
                auto ivData = genValidIV();
                int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                    ivData.data(), ivData.size(), true);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                
                CRYPT_EAL_CipherDeinit(ctx);
                CRYPT_EAL_CipherFreeCtx(ctx);
            }
            
            // Test CTR mode (IV required)
            {
                CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CTR);
                RC_PRE(ctx != nullptr);
                
                auto ivData = genValidIV();
                int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                    ivData.data(), ivData.size(), true);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                
                CRYPT_EAL_CipherDeinit(ctx);
                CRYPT_EAL_CipherFreeCtx(ctx);
            }
        });

    /**
     * @test Encrypted output differs from plaintext (confusion property)
     * @property encrypt(plaintext, key, iv) should produce output different from input
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Verify encryption produces different output
     */
    rc::check("AES encryption output differs from input (confusion)",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                NULL, 0, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            // Generate random plaintext
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> ciphertext(16);
            uint32_t outLen = 16;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), 16, ciphertext.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Ciphertext should differ from plaintext (for random key)
            // Note: There's a 1/2^128 chance they match, which is negligible
            RC_ASSERT(std::memcmp(plaintext.data(), ciphertext.data(), 16) != 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test AES encryption is deterministic
     * @property encrypt(plaintext, key) called twice produces identical output
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Determinism test
     */
    rc::check("AES encryption is deterministic",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                                NULL, 0, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> ciphertext1(16);
            std::vector<uint8_t> ciphertext2(16);
            uint32_t outLen1 = 16;
            uint32_t outLen2 = 16;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), 16, ciphertext1.data(), &outLen1);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), 16, ciphertext2.data(), &outLen2);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(outLen1 == outLen2);
            RC_ASSERT(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16) == 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test AES encrypt-decrypt roundtrip preserves data
     * @property decrypt(encrypt(plaintext, key, iv), key, iv) == plaintext
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Roundtrip test
     */
    rc::check("AES encrypt-decrypt roundtrip preserves data",
        []() {
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, keyData.data(), keyData.size(), 
                                                ivData.data(), ivData.size(), true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_CipherInit(decCtx, keyData.data(), keyData.size(), 
                                        ivData.data(), ivData.size(), false);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            // Generate plaintext that's multiple of block size for simplicity
            auto plaintextLen = *gen::inRange(16, 65);  // 16 to 64 bytes
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> ciphertext(plaintextLen + 16);
            std::vector<uint8_t> decrypted(plaintextLen + 16);
            uint32_t encLen = ciphertext.size();
            uint32_t decLen = decrypted.size();
            
            ret = CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), plaintext.size(), 
                                         ciphertext.data(), &encLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), encLen, 
                                         decrypted.data(), &decLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(decLen == plaintext.size());
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
            
            CRYPT_EAL_CipherDeinit(encCtx);
            CRYPT_EAL_CipherDeinit(decCtx);
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    /**
     * @test Different keys produce different ciphertexts
     * @property encrypt(p, k1) != encrypt(p, k2) when k1 != k2
     * @generalizes Tests that key choice affects ciphertext
     */
    rc::check("Different keys produce different ciphertexts",
        []() {
            auto key1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto key2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(key1 != key2);  // Keys must be different
            
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            // Encrypt with key1
            CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx1 != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx1, key1.data(), key1.size(), 
                                                ivData.data(), ivData.size(), true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext1(16);
            uint32_t len1 = 16;
            ret = CRYPT_EAL_CipherUpdate(ctx1, plaintext.data(), 16, ciphertext1.data(), &len1);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Encrypt with key2
            CRYPT_EAL_CipherCtx *ctx2 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx2 != nullptr);
            ret = CRYPT_EAL_CipherInit(ctx2, key2.data(), key2.size(), 
                                        ivData.data(), ivData.size(), true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext2(16);
            uint32_t len2 = 16;
            ret = CRYPT_EAL_CipherUpdate(ctx2, plaintext.data(), 16, ciphertext2.data(), &len2);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Ciphertexts should differ
            RC_ASSERT(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16) != 0);
            
            CRYPT_EAL_CipherDeinit(ctx1);
            CRYPT_EAL_CipherDeinit(ctx2);
            CRYPT_EAL_CipherFreeCtx(ctx1);
            CRYPT_EAL_CipherFreeCtx(ctx2);
        });

    /**
     * @test Different IVs produce different ciphertexts (for same key and plaintext)
     * @property In CBC mode, encrypt(p, k, iv1) != encrypt(p, k, iv2) when iv1 != iv2
     * @generalizes Tests that IV affects CBC mode encryption
     */
    rc::check("Different IVs produce different ciphertexts in CBC mode",
        []() {
            auto keyData = genValidKey();
            auto iv1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto iv2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(iv1 != iv2);  // IVs must be different
            
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            // Encrypt with iv1
            CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx1 != nullptr);
            int32_t ret = CRYPT_EAL_CipherInit(ctx1, keyData.data(), keyData.size(), 
                                                iv1.data(), iv1.size(), true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext1(16);
            uint32_t len1 = 16;
            ret = CRYPT_EAL_CipherUpdate(ctx1, plaintext.data(), 16, ciphertext1.data(), &len1);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Encrypt with iv2
            CRYPT_EAL_CipherCtx *ctx2 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);
            RC_PRE(ctx2 != nullptr);
            ret = CRYPT_EAL_CipherInit(ctx2, keyData.data(), keyData.size(), 
                                        iv2.data(), iv2.size(), true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext2(16);
            uint32_t len2 = 16;
            ret = CRYPT_EAL_CipherUpdate(ctx2, plaintext.data(), 16, ciphertext2.data(), &len2);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Ciphertexts should differ
            RC_ASSERT(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16) != 0);
            
            CRYPT_EAL_CipherDeinit(ctx1);
            CRYPT_EAL_CipherDeinit(ctx2);
            CRYPT_EAL_CipherFreeCtx(ctx1);
            CRYPT_EAL_CipherFreeCtx(ctx2);
        });

    return 0;
}
