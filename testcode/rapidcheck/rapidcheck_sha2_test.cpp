/**
 * @file rapidcheck_sha2_test.cpp
 * @brief RapidCheck property-based tests for SHA-2 hash functions
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"

using namespace rc;

int main() {
    /**
     * @test SHA-256 hash is deterministic
     * @property For all inputs, hash(input) == hash(input)
     * @generalizes SDV_CRYPT_EAL_SHA2_API_TC003 - Update and final test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c:145-200
     */
    rc::check("SHA-256 hash is deterministic",
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
            
            RC_ASSERT(len1 == 32);
            RC_ASSERT(len2 == 32);
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_EAL_MdFreeCtx(ctx1);
            CRYPT_EAL_MdFreeCtx(ctx2);
        });

    /**
     * @test SHA-256 output size is always 32 bytes
     * @property For all inputs, len(hash(input)) == 32
     * @generalizes SDV_CRYPT_EAL_SHA2_API_TC002 - Digest length test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c:109-123
     */
    rc::check("SHA-256 output size is always 32 bytes",
        [](const std::vector<uint8_t> &input) {
            RC_ASSERT(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA256) == 32);
            
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_MdInit(ctx);
            CRYPT_EAL_MdUpdate(ctx, input.data(), input.size());
            
            uint8_t hash[64];
            uint32_t len = 64;
            
            int32_t ret = CRYPT_EAL_MdFinal(ctx, hash, &len);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(len == 32);
            
            CRYPT_EAL_MdFreeCtx(ctx);
        });

    /**
     * @test SHA-512 output size is always 64 bytes
     * @property For all inputs, len(hash(input)) == 64
     * @generalizes SDV_CRYPT_EAL_SHA2_API_TC002 - Digest length test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c:109-123
     */
    rc::check("SHA-512 output size is always 64 bytes",
        [](const std::vector<uint8_t> &input) {
            RC_ASSERT(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA512) == 64);
            
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA512);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_MdInit(ctx);
            CRYPT_EAL_MdUpdate(ctx, input.data(), input.size());
            
            uint8_t hash[64];
            uint32_t len = 64;
            
            int32_t ret = CRYPT_EAL_MdFinal(ctx, hash, &len);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(len == 64);
            
            CRYPT_EAL_MdFreeCtx(ctx);
        });

    /**
     * @test SHA-224 output size is always 28 bytes
     * @property For all inputs, len(hash(input)) == 28
     * @generalizes SDV_CRYPT_EAL_SHA2_API_TC002 - Digest length test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c:109-123
     */
    rc::check("SHA-224 output size is always 28 bytes",
        [](const std::vector<uint8_t> &input) {
            RC_ASSERT(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA224) == 28);
            
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA224);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_MdInit(ctx);
            CRYPT_EAL_MdUpdate(ctx, input.data(), input.size());
            
            uint8_t hash[64];
            uint32_t len = 64;
            
            int32_t ret = CRYPT_EAL_MdFinal(ctx, hash, &len);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(len == 28);
            
            CRYPT_EAL_MdFreeCtx(ctx);
        });

    /**
     * @test SHA-384 output size is always 48 bytes
     * @property For all inputs, len(hash(input)) == 48
     * @generalizes SDV_CRYPT_EAL_SHA2_API_TC002 - Digest length test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c:109-123
     */
    rc::check("SHA-384 output size is always 48 bytes",
        [](const std::vector<uint8_t> &input) {
            RC_ASSERT(CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SHA384) == 48);
            
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA384);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_MdInit(ctx);
            CRYPT_EAL_MdUpdate(ctx, input.data(), input.size());
            
            uint8_t hash[64];
            uint32_t len = 64;
            
            int32_t ret = CRYPT_EAL_MdFinal(ctx, hash, &len);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(len == 48);
            
            CRYPT_EAL_MdFreeCtx(ctx);
        });

    /**
     * @test SHA-256 incremental hashing equals single update
     * @property hash(a+b) == hash(a) then hash(b)
     * @generalizes SDV_CRYPT_EAL_SHA2_FUNC_TC003 - Multi-update test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c
     */
    rc::check("SHA-256 incremental hashing equals single update",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 1);
            
            size_t splitPoint = *gen::inRange<size_t>(1, input.size());
            
            CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_MdInit(ctx1);
            CRYPT_EAL_MdInit(ctx2);
            
            CRYPT_EAL_MdUpdate(ctx1, input.data(), input.size());
            
            CRYPT_EAL_MdUpdate(ctx2, input.data(), splitPoint);
            CRYPT_EAL_MdUpdate(ctx2, input.data() + splitPoint, input.size() - splitPoint);
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_EAL_MdFinal(ctx1, hash1, &len1);
            CRYPT_EAL_MdFinal(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) == 0);
            
            CRYPT_EAL_MdFreeCtx(ctx1);
            CRYPT_EAL_MdFreeCtx(ctx2);
        });

    /**
     * @test SHA-256 different inputs produce different hashes
     * @property For distinct input pairs, hash(a) != hash(b)
     * @generalizes Collision resistance test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c
     */
    rc::check("SHA-256 different inputs produce different hashes",
        [](const std::vector<uint8_t> &input1, const std::vector<uint8_t> &input2) {
            RC_PRE(input1 != input2);
            RC_PRE(input1.size() > 0 || input2.size() > 0);
            
            CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_MdInit(ctx1);
            CRYPT_EAL_MdInit(ctx2);
            
            if (input1.size() > 0) {
                CRYPT_EAL_MdUpdate(ctx1, input1.data(), input1.size());
            }
            if (input2.size() > 0) {
                CRYPT_EAL_MdUpdate(ctx2, input2.data(), input2.size());
            }
            
            uint8_t hash1[32], hash2[32];
            uint32_t len1 = 32, len2 = 32;
            
            CRYPT_EAL_MdFinal(ctx1, hash1, &len1);
            CRYPT_EAL_MdFinal(ctx2, hash2, &len2);
            
            RC_ASSERT(std::memcmp(hash1, hash2, 32) != 0);
            
            CRYPT_EAL_MdFreeCtx(ctx1);
            CRYPT_EAL_MdFreeCtx(ctx2);
        });

    /**
     * @test SHA-256 copy context produces same hash
     * @property For all inputs, hash_dup(ctx) == hash(ctx)
     * @generalizes SDV_CRYPT_EAL_SHA2_COPY_CTX_FUNC_TC001 - Copy context test
     * @see testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c
     */
    rc::check("SHA-256 copy context produces same hash",
        [](const std::vector<uint8_t> &input) {
            CRYPT_EAL_MdCtx *ctx1 = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
            RC_PRE(ctx1 != nullptr);
            
            CRYPT_EAL_MdInit(ctx1);
            CRYPT_EAL_MdUpdate(ctx1, input.data(), input.size());
            
            CRYPT_EAL_MdCtx *ctx2 = CRYPT_EAL_MdDupCtx(ctx1);
            RC_PRE(ctx2 != nullptr);
            
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