/**
 * @file rapidcheck_edge_test.cpp
 * @brief RapidCheck property-based tests for edge cases using PUBLIC APIs only
 * 
 * IMPORTANT: This file tests PUBLIC APIs (CRYPT_EAL_*) only.
 * Internal functions (CRYPT_AES_*, CRYPT_SM3_*, etc.) are NOT tested directly
 * because they assume inputs are already validated by the upper layer.
 * 
 * Testing internal functions with NULL inputs will crash - this is expected
 * behavior, not a bug. The public API handles input validation.
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

int main() {
    /**
     * @test Cipher public API handles null ctx
     * @property CRYPT_EAL_CipherUpdate returns error for null ctx
     * @generalizes Safety property - null pointer handling in PUBLIC API
     */
    rc::check("CRYPT_EAL_CipherUpdate returns error for null ctx",
        []() {
            uint8_t data[16] = {0};
            uint8_t out[32];
            uint32_t outLen = 32;
            
            int32_t ret = CRYPT_EAL_CipherUpdate(NULL, data, 16, out, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test Cipher public API handles null output buffer
     * @property CRYPT_EAL_CipherUpdate returns error for null output
     */
    rc::check("CRYPT_EAL_CipherUpdate returns error for null output",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(ctx != nullptr);
            
            uint8_t key[16] = {0};
            int32_t ret = CRYPT_EAL_CipherInit(ctx, key, 16, NULL, 0, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            uint8_t data[16] = {0};
            uint32_t outLen = 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, data, 16, NULL, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test Cipher public API handles null output length
     * @property CRYPT_EAL_CipherUpdate returns error for null outLen
     */
    rc::check("CRYPT_EAL_CipherUpdate returns error for null outLen",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(ctx != nullptr);
            
            uint8_t key[16] = {0};
            int32_t ret = CRYPT_EAL_CipherInit(ctx, key, 16, NULL, 0, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            uint8_t data[16] = {0};
            uint8_t out[32];
            
            ret = CRYPT_EAL_CipherUpdate(ctx, data, 16, out, NULL);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test Cipher init with null key
     * @property CRYPT_EAL_CipherInit returns error for null key
     */
    rc::check("CRYPT_EAL_CipherInit returns error for null key",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(ctx != nullptr);
            
            uint8_t iv[16] = {0};
            int32_t ret = CRYPT_EAL_CipherInit(ctx, NULL, 16, iv, 16, true);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test Cipher final with null ctx
     * @property CRYPT_EAL_CipherFinal returns error for null ctx
     */
    rc::check("CRYPT_EAL_CipherFinal returns error for null ctx",
        []() {
            uint8_t out[32];
            uint32_t outLen = 32;
            
            int32_t ret = CRYPT_EAL_CipherFinal(NULL, out, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test MD public API handles null ctx
     * @property CRYPT_EAL_MdUpdate returns error for null ctx
     */
    rc::check("CRYPT_EAL_MdUpdate returns error for null ctx",
        []() {
            uint8_t data[16] = {0};
            
            int32_t ret = CRYPT_EAL_MdUpdate(NULL, data, 16);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test MD final with null ctx
     * @property CRYPT_EAL_MdFinal returns error for null ctx
     */
    rc::check("CRYPT_EAL_MdFinal returns error for null ctx",
        []() {
            uint8_t out[64];
            uint32_t outLen = 64;
            
            int32_t ret = CRYPT_EAL_MdFinal(NULL, out, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test MD final with null output
     * @property CRYPT_EAL_MdFinal returns error for null output
     */
    rc::check("CRYPT_EAL_MdFinal returns error for null output",
        []() {
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_MdInit(ctx);
            
            uint32_t outLen = 32;
            int32_t ret = CRYPT_EAL_MdFinal(ctx, NULL, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_MdFreeCtx(ctx);
        });

    /**
     * @test Cipher roundtrip with valid inputs
     * @property Using public API, encrypt-decrypt roundtrip works
     */
    rc::check("AES ECB roundtrip via public API",
        [](const std::vector<uint8_t> &keyData, const std::vector<uint8_t> &plaintext) {
            RC_PRE(keyData.size() == 16);
            RC_PRE(plaintext.size() > 0);
            RC_PRE(plaintext.size() % 16 == 0);
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_ECB);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, keyData.data(), 16, NULL, 0, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherInit(decCtx, keyData.data(), 16, NULL, 0, false);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext(plaintext.size() + 16);
            std::vector<uint8_t> decrypted(plaintext.size() + 16);
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
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    /**
     * @test SHA256 hash via public API
     * @property Hash is deterministic via public API
     */
    rc::check("SHA256 hash is deterministic via public API",
        [](const std::vector<uint8_t> &input) {
            CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_MdInit(ctx1);
            CRYPT_EAL_MdInit(ctx2);
            
            CRYPT_EAL_MdUpdate(ctx1, input.data(), input.size());
            CRYPT_EAL_MdUpdate(ctx2, input.data(), input.size());
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_EAL_MdFinal(ctx1, hash1, &len1);
            CRYPT_EAL_MdFinal(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_EAL_MdFreeCtx(ctx1);
            CRYPT_EAL_MdFreeCtx(ctx2);
        });

    return 0;
}