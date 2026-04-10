/**
 * @file rapidcheck_drbg_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_Rand* (DRBG) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/drbg/test_suite_sdv_drbg.c
 *
 * Usage:
 *   ./rapidcheck_drbg_test              # Run all tests
 *   ./rapidcheck_drbg_test --list       # List all test names
 *   ./rapidcheck_drbg_test test1 test2  # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

static bool g_randInitialized = false;

struct DrbgAlgInfo {
    CRYPT_RAND_AlgId id;
    const char *name;
};

static const DrbgAlgInfo DRBG_ALGS[] = {
    { CRYPT_RAND_AES128_CTR, "AES128_CTR" },
    { CRYPT_RAND_AES192_CTR, "AES192_CTR" },
    { CRYPT_RAND_AES256_CTR, "AES256_CTR" },
    { CRYPT_RAND_SM4_CTR,    "SM4_CTR"    },
};
static const size_t DRBG_ALGS_COUNT = sizeof(DRBG_ALGS) / sizeof(DRBG_ALGS[0]);

DrbgAlgInfo genDrbgAlg() {
    auto idx = *gen::inRange<size_t>(0, DRBG_ALGS_COUNT);
    return DRBG_ALGS[idx];
}

static int32_t testEntropyCallback(void *ctx, uint8_t *out, uint32_t outLen) {
    (void)ctx;
    for (uint32_t i = 0; i < outLen; i++) {
        out[i] = *gen::arbitrary<uint8_t>();
    }
    return CRYPT_SUCCESS;
}

static int32_t testNonceCallback(void *ctx, uint8_t *out, uint32_t outLen) {
    (void)ctx;
    for (uint32_t i = 0; i < outLen; i++) {
        out[i] = *gen::arbitrary<uint8_t>();
    }
    return CRYPT_SUCCESS;
}

void test_null_ctx_drbg_bytes() {
    rc::check("CRYPT_EAL_Drbgbytes returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto len = *gen::inRange(1, 64);
            std::vector<uint8_t> out(len);
            int32_t ret = CRYPT_EAL_Drbgbytes(nullptr, out.data(), len);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_output_drbg_bytes() {
    rc::check("CRYPT_EAL_Drbgbytes returns CRYPT_NULL_INPUT when output is NULL",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_Drbgbytes(ctx, nullptr, 32);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_zero_length_drbg_bytes() {
    rc::check("CRYPT_EAL_Drbgbytes returns error when len is 0",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            uint8_t dummy = 0;
            ret = CRYPT_EAL_Drbgbytes(ctx, &dummy, 0);
            RC_ASSERT(ret != CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_output_length_range() {
    rc::check("CRYPT_EAL_Drbgbytes generates requested length (1-1024 bytes)",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto len = *gen::inRange(1, 1025);
            std::vector<uint8_t> out(len);
            ret = CRYPT_EAL_Drbgbytes(ctx, out.data(), len);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_output_not_all_zero() {
    rc::check("CRYPT_EAL_Drbgbytes output is not all zeros",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out(64);
            ret = CRYPT_EAL_Drbgbytes(ctx, out.data(), 64);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            bool allZero = true;
            for (auto b : out) {
                if (b != 0) { allZero = false; break; }
            }
            RC_ASSERT(!allZero);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_multiple_generations_differ() {
    rc::check("Multiple DRBG generations produce different outputs",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out1(32), out2(32);
            ret = CRYPT_EAL_Drbgbytes(ctx, out1.data(), 32);
            RC_PRE(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_Drbgbytes(ctx, out2.data(), 32);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(out1 != out2);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_drbg_seed_succeeds() {
    rc::check("CRYPT_EAL_DrbgSeed succeeds after instantiation",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_DrbgSeed(ctx);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_drbg_seed_with_adin() {
    rc::check("CRYPT_EAL_DrbgSeedWithAdin succeeds with additional input",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto adin = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 64), gen::arbitrary<uint8_t>());
            ret = CRYPT_EAL_DrbgSeedWithAdin(ctx, 
                adin.empty() ? nullptr : adin.data(), adin.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_generate_after_reseed() {
    rc::check("DRBG generates successfully after reseed",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_DrbgSeed(ctx);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out(32);
            ret = CRYPT_EAL_Drbgbytes(ctx, out.data(), 32);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_instantiate_with_pers() {
    rc::check("CRYPT_EAL_DrbgInstantiate succeeds with personalization string",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            auto pers = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 64), gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, 
                pers.empty() ? nullptr : pers.data(), pers.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_generate_with_adin() {
    rc::check("CRYPT_EAL_DrbgbytesWithAdin succeeds with additional input",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            auto adin = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 64), gen::arbitrary<uint8_t>());
            std::vector<uint8_t> out(32);
            ret = CRYPT_EAL_DrbgbytesWithAdin(ctx, out.data(), 32,
                adin.empty() ? nullptr : adin.data(), adin.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_max_request_length() {
    rc::check("CRYPT_EAL_Drbgbytes handles max request length (65536)",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out(65536);
            ret = CRYPT_EAL_Drbgbytes(ctx, out.data(), 65536);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_exceed_max_request_length() {
    rc::check("CRYPT_EAL_Drbgbytes fails for length > 65536",
        []() {
            auto alg = genDrbgAlg();
            CRYPT_RandSeedMethod seedMeth = { testEntropyCallback, testNonceCallback };
            CRYPT_EAL_RndCtx *ctx = CRYPT_EAL_DrbgNew(alg.id, &seedMeth, nullptr);
            RC_PRE(ctx != nullptr);
            
            int32_t ret = CRYPT_EAL_DrbgInstantiate(ctx, nullptr, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out(65537);
            ret = CRYPT_EAL_Drbgbytes(ctx, out.data(), 65537);
            RC_ASSERT(ret != CRYPT_SUCCESS);
            
            CRYPT_EAL_DrbgDeinit(ctx);
        });
}

void test_is_valid_alg_id() {
    rc::check("CRYPT_EAL_RandIsValidAlgId returns correct result",
        []() {
            auto alg = genDrbgAlg();
            RC_ASSERT(CRYPT_EAL_RandIsValidAlgId(alg.id) == true);
            RC_ASSERT(CRYPT_EAL_RandIsValidAlgId((CRYPT_RAND_AlgId)-1) == false);
        });
}

std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx_drbg_bytes", test_null_ctx_drbg_bytes},
    {"null_output_drbg_bytes", test_null_output_drbg_bytes},
    {"zero_length_drbg_bytes", test_zero_length_drbg_bytes},
    {"output_length_range", test_output_length_range},
    {"output_not_all_zero", test_output_not_all_zero},
    {"multiple_generations_differ", test_multiple_generations_differ},
    {"drbg_seed_succeeds", test_drbg_seed_succeeds},
    {"drbg_seed_with_adin", test_drbg_seed_with_adin},
    {"generate_after_reseed", test_generate_after_reseed},
    {"instantiate_with_pers", test_instantiate_with_pers},
    {"generate_with_adin", test_generate_with_adin},
    {"max_request_length", test_max_request_length},
    {"exceed_max_request_length", test_exceed_max_request_length},
    {"is_valid_alg_id", test_is_valid_alg_id},
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