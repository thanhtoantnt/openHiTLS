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
     * @test CRYPT_EAL_CipherUpdate outLen invariant for block cipher modes (CBC, ECB)
     * @property For block cipher modes, outLen <= inLen and outLen % blockSize == 0
     * @invariant Block cipher output is always a multiple of block size
     * @invariant Block cipher output never exceeds input length (no cached data case)
     * @see crypt_eal_cipher.h:149-158
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen is multiple of blockSize and <= inLen for CBC/ECB",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC);
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
            
            RC_ASSERT(outLen <= inputData.size());
            RC_ASSERT(outLen % BLOCKSIZE == 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen invariant for XTS mode
     * @property For XTS mode, outLen <= inLen - 32 and outLen % blockSize == 0
     * @invariant XTS reserves last 2 blocks (32 bytes) for Final
     * @invariant XTS output is always a multiple of block size
     * @see crypt_eal_cipher.h:159-162
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen reserves 2 blocks for XTS Final",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
            RC_PRE(ctx != nullptr);
            
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 32, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inLen = *gen::inRange(32, 128);
            auto inputData = *gen::container<std::vector<uint8_t>>(inLen, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(inputData.size());
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(outLen % BLOCKSIZE == 0);
            RC_ASSERT(outLen <= inputData.size() - 32);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen is always >= 0
     * @property After successful Update, outLen is always non-negative
     * @invariant outLen >= 0 for all cipher modes
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen is always non-negative",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC, 
                                       CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_XTS);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = (algId == CRYPT_CIPHER_SM4_XTS) 
                ? *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>())
                : genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), keyData.size(), 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inLen = (algId == CRYPT_CIPHER_SM4_XTS) 
                ? *gen::inRange(32, 128)
                : *gen::inRange(1, 64);
            auto inputData = *gen::container<std::vector<uint8_t>>(inLen, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(inputData.size() + BLOCKSIZE * 2);
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inputData.size(), output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen >= 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen for CBC with inLen < blockSize
     * @property When inLen < blockSize for CBC/ECB, outLen == 0 (data cached)
     * @invariant Block cipher caches incomplete blocks
     * @see crypt_eal_cipher.h:150-151
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen is 0 when inLen < blockSize for CBC/ECB",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inLen = *gen::inRange(1, BLOCKSIZE);
            auto inputData = *gen::container<std::vector<uint8_t>>(inLen, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(BLOCKSIZE * 2);
            uint32_t outLen = BLOCKSIZE * 2;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inLen, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen for CBC with inLen == blockSize
     * @property When inLen == blockSize for CBC/ECB, outLen == blockSize
     * @invariant Complete block produces output
     * @see crypt_eal_cipher.h:152-153
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen equals blockSize when inLen == blockSize for CBC/ECB",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(BLOCKSIZE, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(BLOCKSIZE * 2);
            uint32_t outLen = BLOCKSIZE * 2;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), BLOCKSIZE, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == BLOCKSIZE);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen for CBC with inLen > blockSize (not multiple)
     * @property When inLen > blockSize and not multiple, outLen == (inLen/blockSize)*blockSize
     * @invariant Only complete blocks are output, remainder cached
     * @see crypt_eal_cipher.h:154-155
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen is floor(inLen/blockSize)*blockSize for CBC/ECB",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_SM4_ECB, CRYPT_CIPHER_SM4_CBC);
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(algId);
            RC_PRE(ctx != nullptr);
            
            auto keyData = genValidKey();
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 16, 
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? nullptr : ivData.data(),
                                               (algId == CRYPT_CIPHER_SM4_ECB) ? 0 : 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inLen = *gen::inRange(BLOCKSIZE + 1, BLOCKSIZE * 4);
            RC_PRE(inLen % BLOCKSIZE != 0);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(inLen, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(inLen + BLOCKSIZE);
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inLen, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == (inLen / BLOCKSIZE) * BLOCKSIZE);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen for XTS with inLen == 32
     * @property When inLen == 32 for XTS, outLen == 0 (both blocks reserved for Final)
     * @invariant XTS reserves minimum 2 blocks
     * @see crypt_eal_cipher.h:161
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen is 0 when inLen == 32 for XTS",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
            RC_PRE(ctx != nullptr);
            
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 32, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inputData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(32);
            uint32_t outLen = 32;
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), 32, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == 0);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test CRYPT_EAL_CipherUpdate outLen for XTS with inLen > 32
     * @property For XTS, outLen == ((inLen/16) - 2) * 16
     * @invariant XTS formula: reserves last 2 blocks
     * @see crypt_eal_cipher.h:161-162
     */
    rc::check("CRYPT_EAL_CipherUpdate outLen follows XTS formula",
        []() {
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_XTS);
            RC_PRE(ctx != nullptr);
            
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = genValidIV();
            
            int32_t ret = CRYPT_EAL_CipherInit(ctx, keyData.data(), 32, ivData.data(), 16, true);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto inLen = *gen::inRange(48, 128);
            auto inputData = *gen::container<std::vector<uint8_t>>(inLen, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> output(inLen);
            uint32_t outLen = output.size();
            
            ret = CRYPT_EAL_CipherUpdate(ctx, inputData.data(), inLen, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            uint32_t expectedOutLen = ((inLen / BLOCKSIZE) - 2) * BLOCKSIZE;
            RC_ASSERT(outLen == expectedOutLen);
            
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