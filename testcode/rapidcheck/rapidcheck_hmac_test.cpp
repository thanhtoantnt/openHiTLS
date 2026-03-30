/**
 * @file rapidcheck_hmac_test.cpp
 * @brief RapidCheck property-based tests for HMAC operations
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
 * 
 * Property-based testing automatically generates thousands of random test cases
 * to find edge cases that fixed unit tests might miss.
 * 
 * NOTE: This test is currently disabled because openHiTLS uses 'export' as a
 * struct member name in crypt_local_types.h:207, which conflicts with the C++
 * reserved keyword 'export'. This test can be enabled once that issue is fixed.
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_hmac.h"
#include "crypt_algid.h"

using namespace rc;

int main() {
    /**
     * @test HMAC is deterministic with same key and message
     * @property For all keys and messages,
     *           hmac(key, message) == hmac(key, message)
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 - HMAC context creation
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC002 - HMAC init test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c:34-54
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c:73-88
     */
    rc::check("HMAC is deterministic with same key and message",
        [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
            RC_PRE(key.size() > 0);
            RC_PRE(key.size() <= 128);
            
            CRYPT_HMAC_Ctx *ctx1 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            CRYPT_HMAC_Ctx *ctx2 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            int ret = CRYPT_HMAC_Init(ctx1, key.data(), key.size());
            RC_PRE(ret == 0);
            ret = CRYPT_HMAC_Init(ctx2, key.data(), key.size());
            RC_PRE(ret == 0);
            
            ret = CRYPT_HMAC_Update(ctx1, message.data(), message.size());
            RC_ASSERT(ret == 0);
            ret = CRYPT_HMAC_Update(ctx2, message.data(), message.size());
            RC_ASSERT(ret == 0);
            
            uint8_t mac1[64], mac2[64];
            uint32_t len1 = 64, len2 = 64;
            
            ret = CRYPT_HMAC_Final(ctx1, mac1, &len1);
            RC_ASSERT(ret == 0);
            ret = CRYPT_HMAC_Final(ctx2, mac2, &len2);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(len1 == len2);
            RC_ASSERT(std::memcmp(mac1, mac2, len1) == 0);
            
            CRYPT_HMAC_FreeCtx(ctx1);
            CRYPT_HMAC_FreeCtx(ctx2);
        });

    /**
     * @test HMAC output size matches expected MAC length
     * @property For all keys and messages, GetMacLen() == actual output length
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC002 - Output length verification
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c:73-88
     */
    rc::check("HMAC output size matches expected MAC length",
        [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
            RC_PRE(key.size() > 0);
            RC_PRE(key.size() <= 128);
            
            CRYPT_HMAC_Ctx *ctx = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx != nullptr);
            
            CRYPT_HMAC_Init(ctx, key.data(), key.size());
            CRYPT_HMAC_Update(ctx, message.data(), message.size());
            
            uint32_t expectedLen = CRYPT_HMAC_GetMacLen(ctx);
            RC_ASSERT(expectedLen > 0);
            
            uint8_t mac[64];
            uint32_t len = 64;
            
            CRYPT_HMAC_Final(ctx, mac, &len);
            RC_ASSERT(len == expectedLen);
            
            CRYPT_HMAC_FreeCtx(ctx);
        });

    /**
     * @test HMAC incremental update equals single update
     * @property For all keys, messages, and split points,
     *           hmac(key, a+b) == hmac(key, a) then hmac(key, b)
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC003 - Multiple update test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c:100-150
     */
    rc::check("HMAC incremental update equals single update",
        [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
            RC_PRE(key.size() > 0);
            RC_PRE(message.size() > 1);
            
            size_t splitPoint = *gen::inRange<size_t>(1, message.size());
            
            CRYPT_HMAC_Ctx *ctx1 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            CRYPT_HMAC_Ctx *ctx2 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_HMAC_Init(ctx1, key.data(), key.size());
            CRYPT_HMAC_Init(ctx2, key.data(), key.size());
            
            CRYPT_HMAC_Update(ctx1, message.data(), message.size());
            
            CRYPT_HMAC_Update(ctx2, message.data(), splitPoint);
            CRYPT_HMAC_Update(ctx2, message.data() + splitPoint, message.size() - splitPoint);
            
            uint8_t mac1[64], mac2[64];
            uint32_t len1 = 64, len2 = 64;
            
            CRYPT_HMAC_Final(ctx1, mac1, &len1);
            CRYPT_HMAC_Final(ctx2, mac2, &len2);
            
            RC_ASSERT(std::memcmp(mac1, mac2, len1) == 0);
            
            CRYPT_HMAC_FreeCtx(ctx1);
            CRYPT_HMAC_FreeCtx(ctx2);
        });

    /**
     * @test HMAC with different keys produces different MACs
     * @property For all distinct key pairs k1 != k2 and all messages,
     *           hmac(k1, message) != hmac(k2, message)
     * @generalizes Key sensitivity test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
     */
    rc::check("HMAC with different keys produces different MACs",
        [](const std::vector<uint8_t> &message) {
            RC_PRE(message.size() > 0);
            
            std::vector<uint8_t> key1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> key2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(key1 != key2);
            
            CRYPT_HMAC_Ctx *ctx1 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            CRYPT_HMAC_Ctx *ctx2 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_HMAC_Init(ctx1, key1.data(), key1.size());
            CRYPT_HMAC_Init(ctx2, key2.data(), key2.size());
            
            CRYPT_HMAC_Update(ctx1, message.data(), message.size());
            CRYPT_HMAC_Update(ctx2, message.data(), message.size());
            
            uint8_t mac1[64], mac2[64];
            uint32_t len1 = 64, len2 = 64;
            
            CRYPT_HMAC_Final(ctx1, mac1, &len1);
            CRYPT_HMAC_Final(ctx2, mac2, &len2);
            
            RC_ASSERT(std::memcmp(mac1, mac2, len1) != 0);
            
            CRYPT_HMAC_FreeCtx(ctx1);
            CRYPT_HMAC_FreeCtx(ctx2);
        });

    /**
     * @test HMAC with different messages produces different MACs
     * @property For all keys and distinct message pairs m1 != m2,
     *           hmac(key, m1) != hmac(key, m2)
     * @generalizes Message sensitivity test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
     */
    rc::check("HMAC with different messages produces different MACs",
        [](const std::vector<uint8_t> &key) {
            RC_PRE(key.size() > 0);
            
            std::vector<uint8_t> message1 = *gen::container<std::vector<uint8_t>>(gen::arbitrary<uint8_t>());
            std::vector<uint8_t> message2 = *gen::container<std::vector<uint8_t>>(gen::arbitrary<uint8_t>());
            RC_PRE(message1 != message2);
            
            CRYPT_HMAC_Ctx *ctx1 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            CRYPT_HMAC_Ctx *ctx2 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_HMAC_Init(ctx1, key.data(), key.size());
            CRYPT_HMAC_Init(ctx2, key.data(), key.size());
            
            CRYPT_HMAC_Update(ctx1, message1.data(), message1.size());
            CRYPT_HMAC_Update(ctx2, message2.data(), message2.size());
            
            uint8_t mac1[64], mac2[64];
            uint32_t len1 = 64, len2 = 64;
            
            CRYPT_HMAC_Final(ctx1, mac1, &len1);
            CRYPT_HMAC_Final(ctx2, mac2, &len2);
            
            RC_ASSERT(std::memcmp(mac1, mac2, len1) != 0);
            
            CRYPT_HMAC_FreeCtx(ctx1);
            CRYPT_HMAC_FreeCtx(ctx2);
        });

    /**
     * @test HMAC reinit produces same MAC
     * @property For all keys and messages,
     *           after reinit, hmac(key, message) == original hmac
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC003 - Reinit test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c:100-130
     */
    rc::check("HMAC reinit produces same MAC",
        [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
            RC_PRE(key.size() > 0);
            
            CRYPT_HMAC_Ctx *ctx = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx != nullptr);
            
            CRYPT_HMAC_Init(ctx, key.data(), key.size());
            CRYPT_HMAC_Update(ctx, message.data(), message.size());
            
            uint8_t mac1[64];
            uint32_t len1 = 64;
            CRYPT_HMAC_Final(ctx, mac1, &len1);
            
            int ret = CRYPT_HMAC_Reinit(ctx);
            RC_ASSERT(ret == 0);
            
            CRYPT_HMAC_Update(ctx, message.data(), message.size());
            
            uint8_t mac2[64];
            uint32_t len2 = 64;
            CRYPT_HMAC_Final(ctx, mac2, &len2);
            
            RC_ASSERT(std::memcmp(mac1, mac2, len1) == 0);
            
            CRYPT_HMAC_FreeCtx(ctx);
        });

    /**
     * @test HMAC duplicate context produces same MAC
     * @property For all keys and messages, DupCtx produces identical results
     * @generalizes SDV_CRYPT_EAL_HMAC_API_TC004 - Context duplication test
     * @see testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
     */
    rc::check("HMAC duplicate context produces same MAC",
        [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {
            RC_PRE(key.size() > 0);
            
            CRYPT_HMAC_Ctx *ctx1 = CRYPT_HMAC_NewCtx(CRYPT_MAC_HMAC_SM3);
            RC_PRE(ctx1 != nullptr);
            
            CRYPT_HMAC_Init(ctx1, key.data(), key.size());
            CRYPT_HMAC_Update(ctx1, message.data(), message.size());
            
            CRYPT_HMAC_Ctx *ctx2 = CRYPT_HMAC_DupCtx(ctx1);
            RC_PRE(ctx2 != nullptr);
            
            uint8_t mac1[64], mac2[64];
            uint32_t len1 = 64, len2 = 64;
            
            CRYPT_HMAC_Final(ctx1, mac1, &len1);
            CRYPT_HMAC_Final(ctx2, mac2, &len2);
            
            RC_ASSERT(std::memcmp(mac1, mac2, len1) == 0);
            
            CRYPT_HMAC_FreeCtx(ctx1);
            CRYPT_HMAC_FreeCtx(ctx2);
        });

    return 0;
}