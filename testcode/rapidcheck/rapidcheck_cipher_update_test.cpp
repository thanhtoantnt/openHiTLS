/**
 * @file rapidcheck_cipher_update_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_CipherUpdate
 * 
 * This file generalizes the unit test SDV_CRYPTO_SM4_UPDATE_API_TC001 from:
 * testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:277-342
 * 
 * The unit test checks specific NULL/invalid inputs one at a time.
 * This PBT test generalizes to random combinations of:
 * - NULL vs valid ctx
 * - NULL vs valid in buffer
 * - NULL vs valid out buffer
 * - NULL vs valid outLen pointer
 * - Zero vs non-zero inLen
 * - Different cipher algorithms (SM4 modes)
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

static const int BLOCKSIZE = 16;

std::vector<uint8_t> genValidKey() {
    return *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
}

std::vector<uint8_t> genValidIV() {
    return *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
}

std::vector<uint8_t> genValidInput() {
    auto len = *gen::inRange(16, 64);
    return *gen::container<std::vector<uint8_t>>(len, gen::arbitrary<uint8_t>());
}

int main() {
    /**
     * @test CRYPT_EAL_CipherUpdate null ctx returns CRYPT_NULL_INPUT
     * @property When ctx is NULL, CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT
     *           regardless of other parameters being valid
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step3 - "ctx is NULL"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:311
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto inputData = genValidInput();
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            int32_t ret = CRYPT_EAL_CipherUpdate(NULL, inputData.data(), inputData.size(),
                                                 output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate null in with non-zero inLen returns CRYPT_NULL_INPUT
     * @property When ctx is valid but in is NULL and inLen != 0,
     *           CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step4 - "in is NULL"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:314
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT when in is NULL and inLen != 0",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, 
                                       CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_XTS);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, NULL, 32, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate null in with zero inLen returns CRYPT_SUCCESS
     * @property When ctx is valid, in is NULL, and inLen == 0,
     *           CRYPT_EAL_CipherUpdate returns CRYPT_SUCCESS
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step6 - "inLen is 0"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:321
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_SUCCESS when in is NULL and inLen is 0",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, 
                                       CRYPT_CIPHER_SM4_CTR);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, NULL, 0, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate null out returns CRYPT_NULL_INPUT
     * @property When ctx is valid but out is NULL,
     *           CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step5 - "out is NULL"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:317
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT when out is NULL",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, 
                                       CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_XTS);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = genValidInput();
            uint32_t outLen = BLOCKSIZE * 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), NULL, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate null outLen returns CRYPT_NULL_INPUT
     * @property When ctx is valid but outLen is NULL,
     *           CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step7 - "outLen is NULL"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:331
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT when outLen is NULL",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, 
                                       CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_XTS);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = genValidInput();
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), NULL);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate with inLen=1 fails for XTS mode
     * @property For SM4_XTS mode, inLen < 32 (two blocks) returns error
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step6 - "XTS algorithm fails"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:324-329
     */
    rc::check("CRYPT_EAL_CipherUpdate fails for XTS mode when inLen < 32",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
            RC_PRE(ctx != nullptr);
            
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 32, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(1, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 1, output.data(), &outLen);
            RC_ASSERT(ret != CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate succeeds with inLen=1 for non-XTS modes
     * @property For non-XTS modes (ECB, CBC, CTR), inLen=1 returns CRYPT_SUCCESS
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step6 - "non-XTS succeeds"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:324-329
     */
    rc::check("CRYPT_EAL_CipherUpdate succeeds with inLen=1 for non-XTS modes",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_CTR);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(1, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 1, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate succeeds with all valid parameters
     * @property When ctx, in, out, outLen are all valid,
     *           CRYPT_EAL_CipherUpdate returns CRYPT_SUCCESS
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001:step2 - "All parameters valid"
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:334
     */
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_SUCCESS with all valid parameters",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_CTR);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = genValidInput();
            std::vector<uint8_t> output(inputData.size() + BLOCKSIZE);
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate output length equals input length for stream modes
     * @property For CTR mode (stream cipher), outLen == inLen after successful update
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001 - Output length verification
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:336
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen equals inLen for CTR mode",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CTR);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = genValidInput();
            std::vector<uint8_t> output(inputData.size());
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == inputData.size());
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate fails when called before Init
     * @property When ctx is in NEW state (not initialized), 
     *           CRYPT_EAL_CipherUpdate returns CRYPT_EAL_ERR_STATE
     * @generalizes State machine property - Update requires Init first
     */
    rc::check("CRYPT_EAL_CipherUpdate fails when called before Init",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_CTR);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto inputData = genValidInput();
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            int32_t ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate fails when called after Final
     * @property When ctx is in FINAL state, CRYPT_EAL_CipherUpdate returns CRYPT_EAL_ERR_STATE
     * @generalizes State machine property - Update cannot be called after Final
     */
    rc::check("CRYPT_EAL_CipherUpdate fails when called after Final",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(32);
            uint32_t outLen = 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 16, output.data(), &outLen);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            uint32_t finalLen = 16;
            ret = CRYPT_EAL_CipherFinal(ctx, output.data() + outLen, &finalLen);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            outLen = 32;
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 16, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate works for both encryption and decryption
     * @property Update works for enc=true and enc=false after proper Init
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001 - enc parameter test
     */
    rc::check("CRYPT_EAL_CipherUpdate works for both encryption and decryption",
        []() {
            auto enc = *gen::arbitrary<bool>();
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_CTR);
            
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, enc);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = genValidInput();
            std::vector<uint8_t> output(inputData.size() + BLOCKSIZE);
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate can be called multiple times
     * @property Multiple sequential Update calls succeed (streaming mode)
     * @generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001 - Multiple update test
     */
    rc::check("CRYPT_EAL_CipherUpdate can be called multiple times",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CTR);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto numUpdates = *gen::inRange(1, 5);
            for (int i = 0; i < numUpdates; i++) {
                auto inputData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
                std::vector<uint8_t> output(16);
                uint32_t outLen = 16;
                
                ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 16, output.data(), &outLen);
                RC_ASSERT(ret == CRYPT_SUCCESS);
            }
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    return 0;
}