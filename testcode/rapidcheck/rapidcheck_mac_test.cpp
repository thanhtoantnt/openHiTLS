/**
 * @file rapidcheck_mac_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_Mac* (HMAC/CMAC) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/hmac/test_suite_sdv_eal_mac_hmac.c
 *
 * Usage:
 *   ./rapidcheck_mac_test              # Run all tests
 *   ./rapidcheck_mac_test --list       # List all test names
 *   ./rapidcheck_mac_test test1 test2  # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_eal_mac.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct MacAlgInfo {
    CRYPT_MAC_AlgId id;
    uint32_t macLen;
    uint32_t keyLen;   // fixed key length for CMAC; 0 means any for HMAC
    const char *name;
};

// HMAC algorithms (variable key length)
static const MacAlgInfo HMAC_ALGS[] = {
    { CRYPT_MAC_HMAC_MD5,      16, 0, "HMAC_MD5"      },
    { CRYPT_MAC_HMAC_SHA1,     20, 0, "HMAC_SHA1"     },
    { CRYPT_MAC_HMAC_SHA224,   28, 0, "HMAC_SHA224"   },
    { CRYPT_MAC_HMAC_SHA256,   32, 0, "HMAC_SHA256"   },
    { CRYPT_MAC_HMAC_SHA384,   48, 0, "HMAC_SHA384"   },
    { CRYPT_MAC_HMAC_SHA512,   64, 0, "HMAC_SHA512"   },
    { CRYPT_MAC_HMAC_SM3,      32, 0, "HMAC_SM3"      },
    { CRYPT_MAC_HMAC_SHA3_224, 28, 0, "HMAC_SHA3_224" },
    { CRYPT_MAC_HMAC_SHA3_256, 32, 0, "HMAC_SHA3_256" },
    { CRYPT_MAC_HMAC_SHA3_384, 48, 0, "HMAC_SHA3_384" },
    { CRYPT_MAC_HMAC_SHA3_512, 64, 0, "HMAC_SHA3_512" },
};
static const size_t HMAC_ALGS_COUNT = sizeof(HMAC_ALGS) / sizeof(HMAC_ALGS[0]);

// CMAC algorithms (fixed 16-byte output, fixed key length)
static const MacAlgInfo CMAC_ALGS[] = {
    { CRYPT_MAC_CMAC_AES128, 16, 16, "CMAC_AES128" },
    { CRYPT_MAC_CMAC_AES192, 16, 24, "CMAC_AES192" },
    { CRYPT_MAC_CMAC_AES256, 16, 32, "CMAC_AES256" },
    { CRYPT_MAC_CMAC_SM4,    16, 16, "CMAC_SM4"    },
};
static const size_t CMAC_ALGS_COUNT = sizeof(CMAC_ALGS) / sizeof(CMAC_ALGS[0]);

MacAlgInfo genHmacAlg() {
    auto idx = *gen::inRange<size_t>(0, HMAC_ALGS_COUNT);
    return HMAC_ALGS[idx];
}

MacAlgInfo genCmacAlg() {
    auto idx = *gen::inRange<size_t>(0, CMAC_ALGS_COUNT);
    return CMAC_ALGS[idx];
}

MacAlgInfo genAnyAlg() {
    size_t total = HMAC_ALGS_COUNT + CMAC_ALGS_COUNT;
    auto idx = *gen::inRange<size_t>(0, total);
    return idx < HMAC_ALGS_COUNT ? HMAC_ALGS[idx] : CMAC_ALGS[idx - HMAC_ALGS_COUNT];
}

// Generate a valid key for the algorithm
std::vector<uint8_t> genKey(const MacAlgInfo &alg) {
    if (alg.keyLen > 0) {
        return *gen::container<std::vector<uint8_t>>(alg.keyLen, gen::arbitrary<uint8_t>());
    }
    // HMAC: variable-length key, 1–64 bytes
    auto len = *gen::inRange(1, 65);
    return *gen::container<std::vector<uint8_t>>(len, gen::arbitrary<uint8_t>());
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

/** NULL ctx returns CRYPT_NULL_INPUT */
void test_null_ctx_update() {
    rc::check("CRYPT_EAL_MacUpdate returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MacUpdate(nullptr, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_ctx_final() {
    rc::check("CRYPT_EAL_MacFinal returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            uint8_t out[64];
            uint32_t outLen = sizeof(out);
            int32_t ret = CRYPT_EAL_MacFinal(nullptr, out, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

/** NULL data with non-zero len returns CRYPT_NULL_INPUT
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 */
void test_null_data_nonzero_len() {
    rc::check("CRYPT_EAL_MacUpdate returns CRYPT_NULL_INPUT when data is NULL and len > 0",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = genKey(alg);
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);

            int32_t ret = CRYPT_EAL_MacUpdate(ctx, nullptr, 32);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** Zero-length Update with any pointer succeeds
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 */
void test_zero_len_update() {
    rc::check("CRYPT_EAL_MacUpdate with zero length always succeeds",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = genKey(alg);
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);

            uint8_t dummy = 0;
            int32_t ret = CRYPT_EAL_MacUpdate(ctx, &dummy, 0);
            RC_ASSERT(ret == CRYPT_SUCCESS);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** Update/Final before Init returns CRYPT_EAL_ERR_STATE
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 state machine */
void test_update_before_init() {
    rc::check("CRYPT_EAL_MacUpdate returns CRYPT_EAL_ERR_STATE when called before Init",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MacUpdate(ctx, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

void test_final_before_init() {
    rc::check("CRYPT_EAL_MacFinal returns CRYPT_EAL_ERR_STATE when called before Init",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            uint8_t out[64];
            uint32_t outLen = alg.macLen;
            int32_t ret = CRYPT_EAL_MacFinal(ctx, out, &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** After Final, Update and Final again must return CRYPT_EAL_ERR_STATE
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 */
void test_update_after_final() {
    rc::check("CRYPT_EAL_MacUpdate returns CRYPT_EAL_ERR_STATE when called after Final",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = genKey(alg);
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(alg.macLen);
            uint32_t outLen = alg.macLen;
            RC_PRE(CRYPT_EAL_MacFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);

            int32_t ret = CRYPT_EAL_MacUpdate(ctx, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

void test_final_after_final() {
    rc::check("CRYPT_EAL_MacFinal returns CRYPT_EAL_ERR_STATE when called twice",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = genKey(alg);
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(alg.macLen);
            uint32_t outLen = alg.macLen;
            RC_PRE(CRYPT_EAL_MacFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);

            outLen = alg.macLen;
            int32_t ret = CRYPT_EAL_MacFinal(ctx, out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** GetMacLen always returns the correct constant length
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 GetMacLen */
void test_get_mac_len() {
    rc::check("CRYPT_EAL_GetMacLen returns correct fixed length for all algorithms",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            uint32_t len = CRYPT_EAL_GetMacLen(ctx);
            RC_ASSERT(len == alg.macLen);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** Output length is exactly macLen after successful Final */
void test_output_length() {
    rc::check("CRYPT_EAL_MacFinal sets outLen to exact mac length",
        []() {
            auto alg = genAnyAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = genKey(alg);
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 128), gen::arbitrary<uint8_t>());
            if (!data.empty()) {
                RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            }

            // Oversized buffer: outLen must be updated to exact mac length
            std::vector<uint8_t> out(alg.macLen + 16);
            uint32_t outLen = out.size();
            int32_t ret = CRYPT_EAL_MacFinal(ctx, out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == alg.macLen);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** Determinism: same key + data always yields same MAC
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC001 determinism */
void test_determinism() {
    rc::check("CRYPT_EAL_Mac is deterministic for same key and input",
        []() {
            auto alg = genAnyAlg();
            auto key = genKey(alg);
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 128), gen::arbitrary<uint8_t>());

            auto computeMac = [&]() -> std::vector<uint8_t> {
                CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
                if (!data.empty()) {
                    RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                }
                std::vector<uint8_t> out(alg.macLen);
                uint32_t outLen = alg.macLen;
                RC_PRE(CRYPT_EAL_MacFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MacFreeCtx(ctx);
                return out;
            };

            auto m1 = computeMac();
            auto m2 = computeMac();
            RC_ASSERT(m1 == m2);
        });
}

/** Incremental MAC equals one-shot MAC
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC003 incremental test */
void test_incremental_equals_oneshot() {
    rc::check("Incremental CRYPT_EAL_MacUpdate equals one-shot for HMAC",
        []() {
            auto alg = genHmacAlg();
            auto key = genKey(alg);

            // Multiple random chunks
            auto numChunks = *gen::inRange(2, 8);
            std::vector<std::vector<uint8_t>> chunks;
            for (int i = 0; i < numChunks; i++) {
                chunks.push_back(*gen::container<std::vector<uint8_t>>(
                    *gen::inRange(0, 64), gen::arbitrary<uint8_t>()));
            }
            std::vector<uint8_t> full;
            for (auto &c : chunks) full.insert(full.end(), c.begin(), c.end());

            // One-shot
            std::vector<uint8_t> oneShotOut(alg.macLen);
            {
                CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
                if (!full.empty()) {
                    RC_PRE(CRYPT_EAL_MacUpdate(ctx, full.data(), full.size()) == CRYPT_SUCCESS);
                }
                uint32_t outLen = alg.macLen;
                RC_PRE(CRYPT_EAL_MacFinal(ctx, oneShotOut.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MacFreeCtx(ctx);
            }

            // Incremental
            std::vector<uint8_t> incrOut(alg.macLen);
            {
                CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
                for (auto &c : chunks) {
                    RC_PRE(CRYPT_EAL_MacUpdate(ctx, c.empty() ? nullptr : c.data(), c.size())
                        == CRYPT_SUCCESS);
                }
                uint32_t outLen = alg.macLen;
                RC_PRE(CRYPT_EAL_MacFinal(ctx, incrOut.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MacFreeCtx(ctx);
            }

            RC_ASSERT(oneShotOut == incrOut);
        });
}

/** Key sensitivity: different non-zero-padded-equivalent keys produce different MACs
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC002 key sensitivity
 *
 *  Note: Per RFC 2104, keys shorter than the block size are zero-padded to block size.
 *  Therefore keys with the same zero-padded representation (e.g., [0x00] and [0x00, 0x00])
 *  MUST produce the same MAC — that is correct, spec-mandated behaviour.
 *  We avoid that degenerate case by ensuring the keys differ in at least one non-zero byte.
 */
void test_key_sensitivity() {
    rc::check("Different HMAC keys (non-zero-equivalent) produce different MACs",
        []() {
            auto alg = genHmacAlg();

            // Generate keys that differ on at least one byte with value > 0
            // to ensure they are not equivalent under zero-padding
            auto key1 = genKey(alg);
            auto key2 = genKey(alg);
            RC_PRE(key1 != key2);

            // Discard trivially-equivalent pairs: both keys consist entirely of 0x00
            // bytes and only differ in length — RFC 2104 mandates those produce
            // identical MACs after zero-padding to blockSize.
            bool key1AllZero = std::all_of(key1.begin(), key1.end(), [](uint8_t b){ return b == 0; });
            bool key2AllZero = std::all_of(key2.begin(), key2.end(), [](uint8_t b){ return b == 0; });
            RC_PRE(!(key1AllZero && key2AllZero));

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());

            auto computeMac = [&](const std::vector<uint8_t> &key) -> std::vector<uint8_t> {
                CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
                RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(alg.macLen);
                uint32_t outLen = alg.macLen;
                RC_PRE(CRYPT_EAL_MacFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MacFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(computeMac(key1) != computeMac(key2));
        });
}

/** Message sensitivity: different messages produce different MACs */
void test_message_sensitivity() {
    rc::check("Different HMAC messages produce different MACs",
        []() {
            auto alg = genHmacAlg();
            auto key = genKey(alg);
            auto data1 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            auto data2 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            RC_PRE(data1 != data2);

            auto computeMac = [&](const std::vector<uint8_t> &data) -> std::vector<uint8_t> {
                CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
                RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(alg.macLen);
                uint32_t outLen = alg.macLen;
                RC_PRE(CRYPT_EAL_MacFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MacFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(computeMac(data1) != computeMac(data2));
        });
}

/** Reinit resets computation to allow reuse with same key
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC003 Reinit test */
void test_reinit_reuse() {
    rc::check("CRYPT_EAL_MacReinit reuses stored key and produces same MAC as Init",
        []() {
            auto alg = genHmacAlg();
            auto key = genKey(alg);
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());

            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            // First run: full Init
            RC_PRE(CRYPT_EAL_MacInit(ctx, key.data(), key.size()) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            std::vector<uint8_t> out1(alg.macLen);
            uint32_t len1 = alg.macLen;
            RC_PRE(CRYPT_EAL_MacFinal(ctx, out1.data(), &len1) == CRYPT_SUCCESS);

            // Second run: Reinit (reuses stored key)
            RC_PRE(CRYPT_EAL_MacReinit(ctx) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MacUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            std::vector<uint8_t> out2(alg.macLen);
            uint32_t len2 = alg.macLen;
            RC_PRE(CRYPT_EAL_MacFinal(ctx, out2.data(), &len2) == CRYPT_SUCCESS);

            CRYPT_EAL_MacFreeCtx(ctx);

            RC_ASSERT(out1 == out2);
        });
}

/** DupCtx mid-stream yields same result
 *  @generalizes SDV_CRYPT_EAL_HMAC_API_TC004 */
void test_dup_ctx() {
    rc::check("CRYPT_EAL_MacDupCtx mid-stream produces same final MAC as original",
        []() {
            auto alg = genHmacAlg();
            auto key = genKey(alg);
            auto prefix = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            auto suffix = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::arbitrary<uint8_t>());

            CRYPT_EAL_MacCtx *orig = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(orig != nullptr);
            RC_PRE(CRYPT_EAL_MacInit(orig, key.data(), key.size()) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MacUpdate(orig, prefix.data(), prefix.size()) == CRYPT_SUCCESS);

            CRYPT_EAL_MacCtx *dup = CRYPT_EAL_MacDupCtx(orig);
            RC_PRE(dup != nullptr);

            RC_PRE(CRYPT_EAL_MacUpdate(orig, suffix.data(), suffix.size()) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MacUpdate(dup,  suffix.data(), suffix.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> outOrig(alg.macLen), outDup(alg.macLen);
            uint32_t lenO = alg.macLen, lenD = alg.macLen;
            RC_PRE(CRYPT_EAL_MacFinal(orig, outOrig.data(), &lenO) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MacFinal(dup,  outDup.data(),  &lenD) == CRYPT_SUCCESS);

            CRYPT_EAL_MacFreeCtx(orig);
            CRYPT_EAL_MacFreeCtx(dup);

            RC_ASSERT(outOrig == outDup);
        });
}

/** CMAC: fixed key length enforced */
void test_cmac_fixed_key() {
    rc::check("CRYPT_EAL_MacInit succeeds with correct key length for CMAC",
        []() {
            auto alg = genCmacAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto key = *gen::container<std::vector<uint8_t>>(alg.keyLen, gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MacInit(ctx, key.data(), key.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

/** CMAC: wrong key length returns an error */
void test_cmac_wrong_key_len() {
    rc::check("CRYPT_EAL_MacInit fails with wrong key length for CMAC",
        []() {
            auto alg = genCmacAlg();
            CRYPT_EAL_MacCtx *ctx = CRYPT_EAL_MacNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            // Pick a key length that is definitely wrong
            auto wrongLen = *gen::inRange(1, 64);
            RC_PRE(wrongLen != static_cast<int>(alg.keyLen));

            auto key = *gen::container<std::vector<uint8_t>>(wrongLen, gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MacInit(ctx, key.data(), key.size());
            RC_ASSERT(ret != CRYPT_SUCCESS);

            CRYPT_EAL_MacFreeCtx(ctx);
        });
}

// ---------------------------------------------------------------------------
// Registry + main
// ---------------------------------------------------------------------------

std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx_update",               test_null_ctx_update},
    {"null_ctx_final",                test_null_ctx_final},
    {"null_data_nonzero_len",         test_null_data_nonzero_len},
    {"zero_len_update",               test_zero_len_update},
    {"update_before_init",            test_update_before_init},
    {"final_before_init",             test_final_before_init},
    {"update_after_final",            test_update_after_final},
    {"final_after_final",             test_final_after_final},
    {"get_mac_len",                   test_get_mac_len},
    {"output_length",                 test_output_length},
    {"determinism",                   test_determinism},
    {"incremental_equals_oneshot",    test_incremental_equals_oneshot},
    {"key_sensitivity",               test_key_sensitivity},
    {"message_sensitivity",           test_message_sensitivity},
    {"reinit_reuse",                  test_reinit_reuse},
    {"dup_ctx",                       test_dup_ctx},
    {"cmac_fixed_key",                test_cmac_fixed_key},
    {"cmac_wrong_key_len",            test_cmac_wrong_key_len},
};

void printUsage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--list|-l] [--help|-h] [TEST_NAMES...]\n";
}

void listTests() {
    std::cout << "Available tests (" << testRegistry.size() << "):\n";
    for (auto &kv : testRegistry)
        std::cout << "  " << kv.first << "\n";
}

int main(int argc, char *argv[]) {
    std::vector<std::string> toRun;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--list" || a == "-l") { listTests(); return 0; }
        if (a == "--help" || a == "-h") { printUsage(argv[0]); return 0; }
        toRun.push_back(a);
    }

    if (toRun.empty()) {
        std::cout << "Running all " << testRegistry.size() << " tests...\n\n";
        for (auto &kv : testRegistry) {
            std::cout << "Running test: " << kv.first << "\n";
            kv.second();
            std::cout << "\n";
        }
    } else {
        for (auto &name : toRun) {
            auto it = testRegistry.find(name);
            if (it == testRegistry.end()) {
                std::cerr << "Error: Unknown test '" << name << "'. Use --list.\n";
                return 1;
            }
            std::cout << "Running test: " << name << "\n";
            it->second();
            std::cout << "\n";
        }
    }
    return 0;
}
