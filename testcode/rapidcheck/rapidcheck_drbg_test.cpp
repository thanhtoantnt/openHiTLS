/**
 * @file rapidcheck_drbg_test.cpp
 * @brief RapidCheck property-based tests for DRBG with FSM oracle
 *
 * Generalizes unit tests from test_suite_sdv_drbg.c
 * Tests CRYPT_EAL_Drbg* state transitions with proper entropy setup.
 *
 * Usage:
 *   ./rapidcheck_drbg_test              # Run all
 *   ./rapidcheck_drbg_test --list       # List tests
 *   ./rapidcheck_drbg_test drbg_fsm     # Run specific test
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "crypt_eal_rand.h"

using namespace rc;

/* ---- DRBG minimum test data size (from SDV test) ---- */
static constexpr uint32_t kDrbgDataSize = 256;

/* ---- Minimal entropy/nonce seed context ---- */
struct DrbgTestSeed {
    uint8_t entropyData[kDrbgDataSize];
    CRYPT_Data entropy;
    uint8_t nonceData[kDrbgDataSize];
    CRYPT_Data nonce;
};

static int32_t drbgGetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange) {
    (void)strength;
    if (!ctx || !entropy || !lenRange) return CRYPT_NULL_INPUT;
    auto *seed = (DrbgTestSeed *)ctx;
    if (seed->entropy.len > lenRange->max || seed->entropy.len < lenRange->min)
        return CRYPT_DRBG_INVALID_LEN;
    entropy->data = seed->entropy.data;
    entropy->len = seed->entropy.len;
    return CRYPT_SUCCESS;
}

static void drbgCleanEntropy(void *ctx, CRYPT_Data *entropy) { (void)ctx; (void)entropy; }

static int32_t drbgGetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange) {
    (void)strength;
    if (!ctx || !nonce || !lenRange) return CRYPT_NULL_INPUT;
    auto *seed = (DrbgTestSeed *)ctx;
    if (seed->nonce.len > lenRange->max || seed->nonce.len < lenRange->min)
        return CRYPT_DRBG_INVALID_LEN;
    nonce->data = seed->nonce.data;
    nonce->len = seed->nonce.len;
    return CRYPT_SUCCESS;
}

static void drbgCleanNonce(void *ctx, CRYPT_Data *nonce) { (void)ctx; (void)nonce; }

static void initSeedCtx(DrbgTestSeed &seed) {
    memset(seed.entropyData, 0xAB, kDrbgDataSize);
    seed.entropy.data = seed.entropyData;
    seed.entropy.len = kDrbgDataSize;
    memset(seed.nonceData, 0xCD, kDrbgDataSize);
    seed.nonce.data = seed.nonceData;
    seed.nonce.len = kDrbgDataSize;
}

/* ================================================================
 * Test 1: DRBG FSM — happy path: new → instantiate → bytes → reseed → bytes
 * ================================================================ */
static void test_drbg_fsm() {
    rc::check("drbg_new→instantiate→bytes→reseed→bytes cycle",
        []() {
            DrbgTestSeed seed;
            initSeedCtx(seed);

            CRYPT_RandSeedMethod meth{};
            meth.getEntropy = drbgGetEntropy;
            meth.cleanEntropy = drbgCleanEntropy;
            meth.getNonce = drbgGetNonce;
            meth.cleanNonce = drbgCleanNonce;

            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &meth, &seed);
            RC_PRE(ctx != nullptr);

            // CREATED → DrbgInstantiate → INSTANTIATED
            RC_ASSERT(CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0) == CRYPT_SUCCESS);

            // INSTANTIATED → Drbgbytes → output
            uint8_t out[32];
            RC_ASSERT(CRYPT_EAL_Drbgbytes(ctx, out, sizeof(out)) == CRYPT_SUCCESS);

            // INSTANTIATED → DrbgReseed → INSTANTIATED
            RC_ASSERT(CRYPT_EAL_DrbgSeed(ctx) == CRYPT_SUCCESS);

            // After reseed → bytes again
            uint8_t out2[32];
            RC_ASSERT(CRYPT_EAL_Drbgbytes(ctx, out2, sizeof(out2)) == CRYPT_SUCCESS);

            // Determinism: same DRBG produces same output for same request size
            // (not checking equality here since reseed changes state)

            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

/* ================================================================
 * Test 2: Invalid state — Drbgbytes before DrbgInstantiate
 * ================================================================ */
static void test_invalid_state() {
    rc::check("drbgbytes before instantiate returns ERR_RAND_NO_WORKING",
        []() {
            DrbgTestSeed seed;
            initSeedCtx(seed);
            CRYPT_RandSeedMethod meth{};
            meth.getEntropy = drbgGetEntropy;
            meth.cleanEntropy = drbgCleanEntropy;
            meth.getNonce = drbgGetNonce;
            meth.cleanNonce = drbgCleanNonce;

            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(CRYPT_RAND_SHA256, &meth, &seed);
            RC_PRE(ctx != nullptr);

            // CREATED state (not instantiated) → bytes should fail
            uint8_t out[32];
            RC_ASSERT(CRYPT_EAL_Drbgbytes(ctx, out, sizeof(out)) == CRYPT_EAL_ERR_RAND_NO_WORKING);

            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

/* ================================================================
 * Test 3: Null input handling
 * ================================================================ */
static void test_null_inputs() {
    rc::check("CRYPT_EAL_DrbgNew returns NULL for invalid alg id",
        []() {
            int idInt = *gen::inRange(999, 9999); CRYPT_RAND_AlgId id = (CRYPT_RAND_AlgId)idInt;
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(id, nullptr, nullptr);
            RC_ASSERT(ctx == nullptr);
        });
}

/* ================================================================
 * Main + Registry
 * ================================================================ */
static std::map<std::string, void(*)()> testRegistry = {
    {"drbg_fsm",        test_drbg_fsm},
    {"invalid_state",   test_invalid_state},
    {"null_inputs",     test_null_inputs},
};

int main(int argc, char **argv) {
    printf("DRBG PBT (FSM) — %s %s\n\n", __DATE__, __TIME__);
    if (argc > 1 && strcmp(argv[1], "--list") == 0) {
        for (auto &[name, func] : testRegistry) printf("  %s\n", name.c_str());
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [test_name ...]\n  --list  List tests\n", argv[0]);
        return 0;
    }
    auto run = [](const char *name, auto fn) {
        printf("Running test: %s\n", name);
        fn();
        printf("\n");
    };
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            auto it = testRegistry.find(argv[i]);
            if (it == testRegistry.end()) {
                std::cerr << "Error: Unknown test '" << argv[i] << "'. Use --list.\n";
                return 1;
            }
            run(argv[i], it->second);
        }
    } else {
        for (auto &[name, fn] : testRegistry) run(name.c_str(), fn);
    }
    return 0;
}
