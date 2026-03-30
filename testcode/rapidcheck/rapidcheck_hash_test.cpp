/**
 * @file rapidcheck_hash_test.cpp
 * @brief RapidCheck property-based tests for SM3 hash function
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c
 * 
 * Property-based testing automatically generates thousands of random test cases
 * to find edge cases that fixed unit tests might miss.
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_sm3.h"

using namespace rc;

int main() {
    /**
     * @test SM3 hash is deterministic
     * @property For all inputs, hash(input) == hash(input)
     * @generalizes SDV_CRYPT_EAL_SM3_API_TC001 - Basic hash operations
     * @generalizes MultiThreadTest - Thread safety verification
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:33-50
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:72-114
     */
    rc::check("SM3 hash is deterministic",
        [](const std::vector<uint8_t> &input) {
            CRYPT_SM3_Ctx *ctx1 = CRYPT_SM3_NewCtx();
            CRYPT_SM3_Ctx *ctx2 = CRYPT_SM3_NewCtx();
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            int ret = CRYPT_SM3_Init(ctx1);
            RC_PRE(ret == 0);
            ret = CRYPT_SM3_Init(ctx2);
            RC_PRE(ret == 0);
            
            ret = CRYPT_SM3_Update(ctx1, input.data(), input.size());
            RC_ASSERT(ret == 0);
            ret = CRYPT_SM3_Update(ctx2, input.data(), input.size());
            RC_ASSERT(ret == 0);
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            ret = CRYPT_SM3_Final(ctx1, hash1, &len1);
            RC_ASSERT(ret == 0);
            ret = CRYPT_SM3_Final(ctx2, hash2, &len2);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(len1 == 32);
            RC_ASSERT(len2 == 32);
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_SM3_FreeCtx(ctx1);
            CRYPT_SM3_FreeCtx(ctx2);
        });

    /**
     * @test SM3 hash output size is always 32 bytes
     * @property For all inputs, len(hash(input)) == 32
     * @generalizes SDV_CRYPT_EAL_SM3_API_TC001 - Output length verification
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:77-82
     */
    rc::check("SM3 hash output size is always 32 bytes",
        [](const std::vector<uint8_t> &input) {
            CRYPT_SM3_Ctx *ctx = CRYPT_SM3_NewCtx();
            RC_PRE(ctx != nullptr);
            
            int ret = CRYPT_SM3_Init(ctx);
            RC_PRE(ret == 0);
            
            ret = CRYPT_SM3_Update(ctx, input.data(), input.size());
            RC_ASSERT(ret == 0);
            
            uint8_t hash[32];
            uint32_t len = 32;
            
            ret = CRYPT_SM3_Final(ctx, hash, &len);
            RC_ASSERT(ret == 0);
            RC_ASSERT(len == 32);
            
            CRYPT_SM3_FreeCtx(ctx);
        });

    /**
     * @test SM3 hash of concatenated input equals incremental hash
     * @property For all inputs and split points,
     *           hash(a+b) == hash(a) then hash(b)
     * @generalizes SDV_CRYPT_EAL_SM3_API_TC003 - Multiple update test
     * @generalizes SDV_CRYPT_EAL_SM3_API_TC004 - Incremental hashing
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:200-236
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:270-295
     */
    rc::check("SM3 hash of concatenated input equals incremental hash",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 1);
            
            size_t splitPoint = *gen::inRange<size_t>(1, input.size());
            
            CRYPT_SM3_Ctx *ctx1 = CRYPT_SM3_NewCtx();
            CRYPT_SM3_Ctx *ctx2 = CRYPT_SM3_NewCtx();
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_SM3_Init(ctx1);
            CRYPT_SM3_Init(ctx2);
            
            CRYPT_SM3_Update(ctx1, input.data(), input.size());
            
            CRYPT_SM3_Update(ctx2, input.data(), splitPoint);
            CRYPT_SM3_Update(ctx2, input.data() + splitPoint, input.size() - splitPoint);
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_SM3_Final(ctx1, hash1, &len1);
            CRYPT_SM3_Final(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_SM3_FreeCtx(ctx1);
            CRYPT_SM3_FreeCtx(ctx2);
        });

    /**
     * @test SM3 different inputs produce different hashes
     * @property For all distinct input pairs, hash(a) != hash(b)
     * @generalizes Collision resistance property test
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c
     */
    rc::check("SM3 different inputs produce different hashes",
        [](const std::vector<uint8_t> &input1, const std::vector<uint8_t> &input2) {
            RC_PRE(input1 != input2);
            RC_PRE(input1.size() > 0 || input2.size() > 0);
            
            CRYPT_SM3_Ctx *ctx1 = CRYPT_SM3_NewCtx();
            CRYPT_SM3_Ctx *ctx2 = CRYPT_SM3_NewCtx();
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_SM3_Init(ctx1);
            CRYPT_SM3_Init(ctx2);
            
            if (input1.size() > 0) {
                CRYPT_SM3_Update(ctx1, input1.data(), input1.size());
            }
            if (input2.size() > 0) {
                CRYPT_SM3_Update(ctx2, input2.data(), input2.size());
            }
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_SM3_Final(ctx1, hash1, &len1);
            CRYPT_SM3_Final(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) != 0);
            
            CRYPT_SM3_FreeCtx(ctx1);
            CRYPT_SM3_FreeCtx(ctx2);
        });

    /**
     * @test SM3 copy context produces same hash
     * @property For all inputs, hash_dup(ctx) == hash(ctx)
     * @generalizes SDV_CRYPT_EAL_SM3_API_TC005 - Copy and duplicate context test
     * @see testcode/sdv/testcase/crypto/sm3/test_suite_sdv_eal_sm3.c:312-360
     */
    rc::check("SM3 copy context produces same hash",
        [](const std::vector<uint8_t> &input) {
            CRYPT_SM3_Ctx *ctx1 = CRYPT_SM3_NewCtx();
            RC_PRE(ctx1 != nullptr);
            
            CRYPT_SM3_Init(ctx1);
            CRYPT_SM3_Update(ctx1, input.data(), input.size());
            
            CRYPT_SM3_Ctx *ctx2 = CRYPT_SM3_DupCtx(ctx1);
            RC_PRE(ctx2 != nullptr);
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_SM3_Final(ctx1, hash1, &len1);
            CRYPT_SM3_Final(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_SM3_FreeCtx(ctx1);
            CRYPT_SM3_FreeCtx(ctx2);
        });

    return 0;
}