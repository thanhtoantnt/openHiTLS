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
 * 
 * Usage:
 *   ./rapidcheck_cipher_update_test              # Run all tests
 *   ./rapidcheck_cipher_update_test --list       # List all test names
 *   ./rapidcheck_cipher_update_test test1 test2  # Run specific tests
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

// Test functions - each test is a separate function for easier debugging

void test_null_ctx() {
    rc::check("CRYPT_EAL_CipherUpdate returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto inputData = genValidInput();
            std::vector<uint8_t> output(BLOCKSIZE * 32);
            uint32_t outLen = BLOCKSIZE * 32;
            
            int32_t ret = CRYPT_EAL_CipherUpdate(NULL, inputData.data(), inputData.size(),
                                                 output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_in_nonzero_len() {
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
}

void test_null_in_zero_len() {
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
}

void test_null_out() {
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
}

void test_null_outlen() {
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
}

void test_xts_small_input() {
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
}

void test_non_xts_small_input() {
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
}

void test_all_valid_params() {
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
}

void test_ctr_outlen_equals_inlen() {
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
}

void test_block_cipher_outlen_invariant() {
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
}

void test_xts_reserves_2_blocks() {
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
}

void test_xts_outlen_multiple_of_blocksize() {
    rc::check("CRYPT_EAL_CipherUpdate outLen is multiple of BLOCKSIZE for XTS",
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
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherFreeCtx(ctx);
        });
}

void test_outlen_non_negative() {
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
}

void test_cbc_small_input() {
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
}

void test_cbc_exact_block() {
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
}

void test_cbc_non_block_multiple() {
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
}

void test_xts_32_bytes() {
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
}

void test_xts_formula() {
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
}

void test_update_before_init() {
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
}

void test_update_after_final() {
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
}

void test_enc_dec() {
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
}

void test_multiple_updates() {
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
}

// Test registry
std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx", test_null_ctx},
    {"null_in_nonzero_len", test_null_in_nonzero_len},
    {"null_in_zero_len", test_null_in_zero_len},
    {"null_out", test_null_out},
    {"null_outlen", test_null_outlen},
    {"xts_small_input", test_xts_small_input},
    {"non_xts_small_input", test_non_xts_small_input},
    {"all_valid_params", test_all_valid_params},
    {"ctr_outlen_equals_inlen", test_ctr_outlen_equals_inlen},
    {"block_cipher_outlen_invariant", test_block_cipher_outlen_invariant},
    {"xts_reserves_2_blocks", test_xts_reserves_2_blocks},
    {"xts_outlen_multiple_of_blocksize", test_xts_outlen_multiple_of_blocksize},
    {"outlen_non_negative", test_outlen_non_negative},
    {"cbc_small_input", test_cbc_small_input},
    {"cbc_exact_block", test_cbc_exact_block},
    {"cbc_non_block_multiple", test_cbc_non_block_multiple},
    {"xts_32_bytes", test_xts_32_bytes},
    {"xts_formula", test_xts_formula},
    {"update_before_init", test_update_before_init},
    {"update_after_final", test_update_after_final},
    {"enc_dec", test_enc_dec},
    {"multiple_updates", test_multiple_updates},
};

void printUsage(const char* programName) {
    std::cerr << "Usage: " << programName << " [OPTIONS] [TEST_NAMES...]\n"
              << "\n"
              << "Options:\n"
              << "  --list, -l     List all available test names\n"
              << "  --help, -h     Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << programName << "                          # Run all tests\n"
              << "  " << programName << " --list                   # List all test names\n"
              << "  " << programName << " xts_32_bytes             # Run specific test\n"
              << "  " << programName << " test1 test2 test3        # Run multiple tests\n";
}

void listTests() {
    std::cout << "Available tests:\n";
    for (const auto& [name, func] : testRegistry) {
        std::cout << "  " << name << "\n";
    }
    std::cout << "\nTotal: " << testRegistry.size() << " tests\n";
}

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    std::vector<std::string> testsToRun;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--list" || arg == "-l") {
            listTests();
            return 0;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else {
            testsToRun.push_back(arg);
        }
    }
    
    // Run tests
    if (testsToRun.empty()) {
        // Run all tests
        std::cout << "Running all " << testRegistry.size() << " tests...\n\n";
        for (const auto& [name, func] : testRegistry) {
            std::cout << "Running test: " << name << "\n";
            func();
            std::cout << "\n";
        }
    } else {
        // Run specific tests
        for (const auto& testName : testsToRun) {
            auto it = testRegistry.find(testName);
            if (it != testRegistry.end()) {
                std::cout << "Running test: " << testName << "\n";
                it->second();
                std::cout << "\n";
            } else {
                std::cerr << "Error: Unknown test '" << testName << "'\n";
                std::cerr << "Use --list to see available tests\n";
                return 1;
            }
        }
    }
    
    return 0;
}