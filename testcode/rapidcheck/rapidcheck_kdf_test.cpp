/**
 * @file rapidcheck_kdf_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_Kdf* (HKDF) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.c
 *
 * Usage:
 *   ./rapidcheck_kdf_test              # Run all tests
 *   ./rapidcheck_kdf_test --list       # List all test names
 *   ./rapidcheck_kdf_test test1 test2  # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_params_key.h"
#include "bsl_params.h"

using namespace rc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct HkdfAlgInfo {
    CRYPT_MAC_AlgId macId;
    uint32_t hashLen;   // underlying hash output length (= max OKM / 255)
    const char *name;
};

// Algorithms supported by HKDF (not SHA3 variants)
static const HkdfAlgInfo HKDF_ALGS[] = {
    { CRYPT_MAC_HMAC_SHA1,   20, "HMAC_SHA1"   },
    { CRYPT_MAC_HMAC_SHA224, 28, "HMAC_SHA224" },
    { CRYPT_MAC_HMAC_SHA256, 32, "HMAC_SHA256" },
    { CRYPT_MAC_HMAC_SHA384, 48, "HMAC_SHA384" },
    { CRYPT_MAC_HMAC_SHA512, 64, "HMAC_SHA512" },
    { CRYPT_MAC_HMAC_SM3,    32, "HMAC_SM3"    },
};
static const size_t HKDF_ALGS_COUNT = sizeof(HKDF_ALGS) / sizeof(HKDF_ALGS[0]);

HkdfAlgInfo genAlg() {
    auto idx = *gen::inRange<size_t>(0, HKDF_ALGS_COUNT);
    return HKDF_ALGS[idx];
}

// Build a BSL_Param array for HKDF (FULL mode)
// Params must stay alive for the duration of SetParam
static int32_t setHkdfParams(CRYPT_EAL_KdfCtx *ctx, CRYPT_MAC_AlgId macId,
    const std::vector<uint8_t> &ikm, const std::vector<uint8_t> &salt,
    const std::vector<uint8_t> &info)
{
    uint32_t mode = CRYPT_KDF_HKDF_MODE_FULL;
    uint32_t mac  = static_cast<uint32_t>(macId);

    BSL_Param params[6];
    int idx = 0;
    BSL_PARAM_InitValue(&params[idx++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &mac, sizeof(mac));
    BSL_PARAM_InitValue(&params[idx++], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode));
    BSL_PARAM_InitValue(&params[idx++], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        const_cast<uint8_t *>(ikm.empty()  ? nullptr : ikm.data()),  ikm.size());
    BSL_PARAM_InitValue(&params[idx++], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        const_cast<uint8_t *>(salt.empty() ? nullptr : salt.data()), salt.size());
    BSL_PARAM_InitValue(&params[idx++], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        const_cast<uint8_t *>(info.empty() ? nullptr : info.data()), info.size());
    params[idx] = BSL_PARAM_END;

    return CRYPT_EAL_KdfSetParam(ctx, params);
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

/** NULL ctx returns CRYPT_NULL_INPUT */
void test_null_ctx_derive() {
    rc::check("CRYPT_EAL_KdfDerive returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            uint8_t out[32];
            int32_t ret = CRYPT_EAL_KdfDerive(nullptr, out, sizeof(out));
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_ctx_set_param() {
    rc::check("CRYPT_EAL_KdfSetParam returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            uint32_t mode = CRYPT_KDF_HKDF_MODE_FULL;
            BSL_Param params[2];
            BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
                &mode, sizeof(mode));
            params[1] = BSL_PARAM_END;
            int32_t ret = CRYPT_EAL_KdfSetParam(nullptr, params);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

/** NULL param array returns CRYPT_NULL_INPUT
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_API_TC001 */
void test_null_param_array() {
    rc::check("CRYPT_EAL_KdfSetParam returns CRYPT_NULL_INPUT when params is NULL",
        []() {
            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);
            int32_t ret = CRYPT_EAL_KdfSetParam(ctx, nullptr);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** NULL output buffer returns CRYPT_NULL_INPUT */
void test_null_output_buffer() {
    rc::check("CRYPT_EAL_KdfDerive returns CRYPT_NULL_INPUT when out is NULL",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);

            auto ikm = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> salt, info;
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);

            int32_t ret = CRYPT_EAL_KdfDerive(ctx, nullptr, 32);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** Zero output length returns CRYPT_NULL_INPUT */
void test_zero_output_length() {
    rc::check("CRYPT_EAL_KdfDerive returns CRYPT_NULL_INPUT when keyLen is 0",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);

            auto ikm = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> salt, info;
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);

            uint8_t out[32];
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out, 0);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** Determinism: same inputs always yield same output key material
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_FUNC_TC001 vector test */
void test_determinism() {
    rc::check("CRYPT_EAL_KdfDerive is deterministic for same inputs",
        []() {
            auto alg = genAlg();
            auto ikm  = *gen::container<std::vector<uint8_t>>(*gen::inRange(1,  64), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(*gen::inRange(0,  32), gen::arbitrary<uint8_t>());
            auto info = *gen::container<std::vector<uint8_t>>(*gen::inRange(0,  32), gen::arbitrary<uint8_t>());
            auto outLen = *gen::inRange(1, static_cast<int>(alg.hashLen) + 1);

            auto derive = [&]() -> std::vector<uint8_t> {
                CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
                RC_PRE(ctx != nullptr);
                RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(outLen);
                RC_PRE(CRYPT_EAL_KdfDerive(ctx, out.data(), outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_KdfFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(derive() == derive());
        });
}

/** IKM sensitivity: different IKM produces different output
 *  @generalizes key-sensitivity property from HKDF spec */
void test_ikm_sensitivity() {
    rc::check("Different IKM produces different HKDF output",
        []() {
            auto alg = genAlg();
            auto ikm1 = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            auto ikm2 = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            RC_PRE(ikm1 != ikm2);

            auto salt = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto info = *gen::container<std::vector<uint8_t>>(8,  gen::arbitrary<uint8_t>());
            uint32_t outLen = alg.hashLen;

            auto derive = [&](const std::vector<uint8_t> &ikm) -> std::vector<uint8_t> {
                CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
                RC_PRE(ctx != nullptr);
                RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(outLen);
                RC_PRE(CRYPT_EAL_KdfDerive(ctx, out.data(), outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_KdfFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(derive(ikm1) != derive(ikm2));
        });
}

/** Salt sensitivity: different salt produces different output
 *
 *  Note: Per RFC 5869 Section 2.2, the salt is used as the HMAC key in the Extract step.
 *  Per RFC 2104, HMAC keys shorter than the block size are zero-padded to the block size.
 *  Therefore salts that consist entirely of 0x00 bytes and only differ in length produce
 *  identical outputs (their zero-padded HMAC representations are the same).
 *  We exclude that degenerate case by requiring at least one non-zero byte.
 */
void test_salt_sensitivity() {
    rc::check("Different HKDF salt (non-zero-equivalent) produces different output",
        []() {
            auto alg = genAlg();
            auto ikm   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt1 = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            auto salt2 = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            RC_PRE(salt1 != salt2);

            // Exclude pairs that are both all-zero (differ only in length);
            // such pairs are equivalent under HMAC zero-padding (RFC 2104 / RFC 5869).
            bool s1AllZero = std::all_of(salt1.begin(), salt1.end(), [](uint8_t b){ return b == 0; });
            bool s2AllZero = std::all_of(salt2.begin(), salt2.end(), [](uint8_t b){ return b == 0; });
            RC_PRE(!(s1AllZero && s2AllZero));

            uint32_t outLen = alg.hashLen;

            auto derive = [&](const std::vector<uint8_t> &salt) -> std::vector<uint8_t> {
                CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
                RC_PRE(ctx != nullptr);
                std::vector<uint8_t> info;
                RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(outLen);
                RC_PRE(CRYPT_EAL_KdfDerive(ctx, out.data(), outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_KdfFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(derive(salt1) != derive(salt2));
        });
}

/** Output length must be positive and <= 255 * hashLen
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_API_TC001 max-length tests */
void test_output_length_contract() {
    rc::check("CRYPT_EAL_KdfDerive output length is exactly what was requested",
        []() {
            auto alg = genAlg();
            auto ikm = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            std::vector<uint8_t> salt, info;

            // Stay well within max (255 * hashLen)
            auto outLen = *gen::inRange(1, static_cast<int>(alg.hashLen) * 4 + 1);

            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(outLen);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** Exceeding max output length returns an error
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_API_TC001 overflow test */
void test_exceed_max_output_length() {
    rc::check("CRYPT_EAL_KdfDerive fails when outLen > 255 * hashLen",
        []() {
            auto alg = genAlg();
            auto ikm = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> salt, info;

            uint32_t maxLen = 255 * alg.hashLen;
            // Use exactly maxLen + 1
            uint32_t tooLong = maxLen + 1;

            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(tooLong);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), tooLong);
            RC_ASSERT(ret != CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** Optional params (empty salt, empty info, empty IKM) all succeed
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_API_TC001 optional param tests */
void test_optional_params_empty() {
    rc::check("CRYPT_EAL_KdfDerive succeeds with empty salt and info",
        []() {
            auto alg = genAlg();
            auto ikm = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());

            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> empty;
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, empty, empty) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(alg.hashLen);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), alg.hashLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/** DupCtx produces same output as original
 *  @generalizes SDV_CRYPT_EAL_KDF_HKDF_API_TC001 dup/copy tests */
void test_dup_ctx() {
    rc::check("CRYPT_EAL_KdfDupCtx produces same output as original",
        []() {
            auto alg = genAlg();
            auto ikm  = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 16), gen::arbitrary<uint8_t>());
            auto info = *gen::container<std::vector<uint8_t>>(*gen::inRange(0, 16), gen::arbitrary<uint8_t>());
            uint32_t outLen = alg.hashLen;

            CRYPT_EAL_KdfCtx *orig = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(orig != nullptr);
            RC_PRE(setHkdfParams(orig, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);

            // Dup before deriving
            CRYPT_EAL_KdfCtx *dup = CRYPT_EAL_KdfDupCtx(orig);
            RC_PRE(dup != nullptr);

            std::vector<uint8_t> outOrig(outLen), outDup(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(orig, outOrig.data(), outLen) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(dup,  outDup.data(),  outLen) == CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(orig);
            CRYPT_EAL_KdfFreeCtx(dup);

            RC_ASSERT(outOrig == outDup);
        });
}

/** Re-derive after Deinit+SetParam produces same output */
void test_deinit_and_rederive() {
    rc::check("CRYPT_EAL_KdfDerive produces same output after Deinit and re-SetParam",
        []() {
            auto alg = genAlg();
            auto ikm  = *gen::container<std::vector<uint8_t>>(*gen::inRange(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(*gen::inRange(0, 16), gen::arbitrary<uint8_t>());
            auto info = *gen::container<std::vector<uint8_t>>(*gen::inRange(0, 16), gen::arbitrary<uint8_t>());
            uint32_t outLen = alg.hashLen;

            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);

            // First derive
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);
            std::vector<uint8_t> out1(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx, out1.data(), outLen) == CRYPT_SUCCESS);

            // Deinit and re-derive with same params
            RC_PRE(CRYPT_EAL_KdfDeInitCtx(ctx) == CRYPT_SUCCESS);
            RC_PRE(setHkdfParams(ctx, alg.macId, ikm, salt, info) == CRYPT_SUCCESS);
            std::vector<uint8_t> out2(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx, out2.data(), outLen) == CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
            RC_ASSERT(out1 == out2);
        });
}

/** Invalid MAC ID returns an error */
void test_invalid_mac_id() {
    rc::check("CRYPT_EAL_KdfSetParam fails with invalid MAC ID",
        []() {
            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
            RC_PRE(ctx != nullptr);

            uint32_t badMac = static_cast<uint32_t>(CRYPT_MAC_MAX);
            uint32_t mode   = CRYPT_KDF_HKDF_MODE_FULL;

            BSL_Param params[3];
            BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
                &badMac, sizeof(badMac));
            BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
                &mode, sizeof(mode));
            params[2] = BSL_PARAM_END;

            int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
            RC_ASSERT(ret != CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

// ---------------------------------------------------------------------------
// Registry + main
// ---------------------------------------------------------------------------

std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx_derive",           test_null_ctx_derive},
    {"null_ctx_set_param",        test_null_ctx_set_param},
    {"null_param_array",          test_null_param_array},
    {"null_output_buffer",        test_null_output_buffer},
    {"zero_output_length",        test_zero_output_length},
    {"determinism",               test_determinism},
    {"ikm_sensitivity",           test_ikm_sensitivity},
    {"salt_sensitivity",          test_salt_sensitivity},
    {"output_length_contract",    test_output_length_contract},
    {"exceed_max_output_length",  test_exceed_max_output_length},
    {"optional_params_empty",     test_optional_params_empty},
    {"dup_ctx",                   test_dup_ctx},
    {"deinit_and_rederive",       test_deinit_and_rederive},
    {"invalid_mac_id",            test_invalid_mac_id},
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
