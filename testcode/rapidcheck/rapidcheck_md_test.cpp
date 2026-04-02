/**
 * @file rapidcheck_md_test.cpp
 * @brief RapidCheck property-based tests for CRYPT_EAL_Md* (hash/digest) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/sha2/test_suite_sdv_eal_md_sha2.c
 *   testcode/sdv/testcase/crypto/md5/test_suite_sdv_eal_md5.c
 *   testcode/sdv/testcase/crypto/sha3/test_suite_sdv_eal_md_sha3.c
 *
 * Usage:
 *   ./rapidcheck_md_test              # Run all tests
 *   ./rapidcheck_md_test --list       # List all test names
 *   ./rapidcheck_md_test test1 test2  # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct AlgInfo {
    CRYPT_MD_AlgId id;
    uint32_t digestSize;
    const char *name;
};

// All fixed-output algorithms (excludes SHAKE XOFs)
static const AlgInfo FIXED_ALGS[] = {
    { CRYPT_MD_MD5,      16, "MD5"      },
    { CRYPT_MD_SHA1,     20, "SHA1"     },
    { CRYPT_MD_SHA224,   28, "SHA224"   },
    { CRYPT_MD_SHA256,   32, "SHA256"   },
    { CRYPT_MD_SHA384,   48, "SHA384"   },
    { CRYPT_MD_SHA512,   64, "SHA512"   },
    { CRYPT_MD_SHA3_224, 28, "SHA3_224" },
    { CRYPT_MD_SHA3_256, 32, "SHA3_256" },
    { CRYPT_MD_SHA3_384, 48, "SHA3_384" },
    { CRYPT_MD_SHA3_512, 64, "SHA3_512" },
    { CRYPT_MD_SM3,      32, "SM3"      },
};
static const size_t FIXED_ALGS_COUNT = sizeof(FIXED_ALGS) / sizeof(FIXED_ALGS[0]);

// Generate a random algorithm from the fixed-output list
AlgInfo genAlg() {
    auto idx = *gen::inRange<size_t>(0, FIXED_ALGS_COUNT);
    return FIXED_ALGS[idx];
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

/** Null ctx returns CRYPT_NULL_INPUT for Update/Final */
void test_null_ctx_update() {
    rc::check("CRYPT_EAL_MdUpdate returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MdUpdate(nullptr, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_ctx_final() {
    rc::check("CRYPT_EAL_MdFinal returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            uint8_t out[64];
            uint32_t outLen = sizeof(out);
            int32_t ret = CRYPT_EAL_MdFinal(nullptr, out, &outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

/** Update/Final before Init returns CRYPT_EAL_ERR_STATE
 *  @generalizes SDV_CRYPT_EAL_SHA2_API_TC001 step "Update before Init" */
void test_update_before_init() {
    rc::check("CRYPT_EAL_MdUpdate returns CRYPT_EAL_ERR_STATE when called before Init",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            int32_t ret = CRYPT_EAL_MdUpdate(ctx, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

void test_final_before_init() {
    rc::check("CRYPT_EAL_MdFinal returns CRYPT_EAL_ERR_STATE when called before Init",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            uint8_t out[64];
            uint32_t outLen = alg.digestSize;
            int32_t ret = CRYPT_EAL_MdFinal(ctx, out, &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

/** After Final, Update and Final again must return CRYPT_EAL_ERR_STATE
 *  @generalizes SDV_CRYPT_EAL_SHA2_API_TC001 */
void test_update_after_final() {
    rc::check("CRYPT_EAL_MdUpdate returns CRYPT_EAL_ERR_STATE when called after Final",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(alg.digestSize);
            uint32_t outLen = alg.digestSize;
            RC_PRE(CRYPT_EAL_MdFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);

            // Update after Final
            int32_t ret = CRYPT_EAL_MdUpdate(ctx, data.data(), data.size());
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

void test_final_after_final() {
    rc::check("CRYPT_EAL_MdFinal returns CRYPT_EAL_ERR_STATE when called twice",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> out(alg.digestSize);
            uint32_t outLen = alg.digestSize;
            RC_PRE(CRYPT_EAL_MdFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);

            // Final again
            outLen = alg.digestSize;
            int32_t ret = CRYPT_EAL_MdFinal(ctx, out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_EAL_ERR_STATE);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

/** Output length is exactly digestSize after successful Final
 *  @generalizes SDV_CRYPT_EAL_SHA2_API_TC001 outLen verification */
void test_output_length() {
    rc::check("CRYPT_EAL_MdFinal sets outLen to exact digest size",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 256), gen::arbitrary<uint8_t>());
            if (!data.empty()) {
                RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            }

            // outLen larger than needed: should succeed and be updated to exact size
            std::vector<uint8_t> out(alg.digestSize + 16);
            uint32_t outLen = out.size();
            int32_t ret = CRYPT_EAL_MdFinal(ctx, out.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen == alg.digestSize);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

/** GetDigestSize returns the correct digest size
 *  @generalizes SDV_CRYPT_EAL_SHA2_API_TC001 */
void test_get_digest_size() {
    rc::check("CRYPT_EAL_MdGetDigestSize returns correct digest size",
        []() {
            auto alg = genAlg();
            uint32_t size = CRYPT_EAL_MdGetDigestSize(alg.id);
            RC_ASSERT(size == alg.digestSize);
        });
}

/** Determinism: same input always yields same digest
 *  @generalizes SDV_CRYPT_EAL_SM3_API_TC001 "MultiThreadTest" determinism */
void test_determinism() {
    rc::check("CRYPT_EAL_MdUpdate+Final is deterministic for same input",
        []() {
            auto alg = genAlg();
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 256), gen::arbitrary<uint8_t>());

            auto computeDigest = [&]() -> std::vector<uint8_t> {
                CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
                if (!data.empty()) {
                    RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                }
                std::vector<uint8_t> out(alg.digestSize);
                uint32_t outLen = alg.digestSize;
                RC_PRE(CRYPT_EAL_MdFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MdFreeCtx(ctx);
                return out;
            };

            auto d1 = computeDigest();
            auto d2 = computeDigest();
            RC_ASSERT(d1 == d2);
        });
}

/** Incremental hashing equals one-shot hashing
 *  @generalizes SDV_CRYPT_EAL_SM3_API_TC003/TC004 incremental tests */
void test_incremental_equals_oneshot() {
    rc::check("Incremental CRYPT_EAL_MdUpdate equals one-shot for all algorithms",
        []() {
            auto alg = genAlg();

            // Generate 2-10 chunks
            auto numChunks = *gen::inRange(2, 10);
            std::vector<std::vector<uint8_t>> chunks;
            for (int i = 0; i < numChunks; i++) {
                chunks.push_back(*gen::container<std::vector<uint8_t>>(
                    *gen::inRange(0, 64), gen::arbitrary<uint8_t>()));
            }

            // Concatenate all chunks
            std::vector<uint8_t> full;
            for (auto &c : chunks) full.insert(full.end(), c.begin(), c.end());

            // One-shot digest
            std::vector<uint8_t> oneShot(alg.digestSize);
            {
                CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
                if (!full.empty()) {
                    RC_PRE(CRYPT_EAL_MdUpdate(ctx, full.data(), full.size()) == CRYPT_SUCCESS);
                }
                uint32_t outLen = alg.digestSize;
                RC_PRE(CRYPT_EAL_MdFinal(ctx, oneShot.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MdFreeCtx(ctx);
            }

            // Incremental digest
            std::vector<uint8_t> incremental(alg.digestSize);
            {
                CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
                for (auto &c : chunks) {
                    RC_PRE(CRYPT_EAL_MdUpdate(ctx, c.empty() ? nullptr : c.data(), c.size())
                        == CRYPT_SUCCESS);
                }
                uint32_t outLen = alg.digestSize;
                RC_PRE(CRYPT_EAL_MdFinal(ctx, incremental.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MdFreeCtx(ctx);
            }

            RC_ASSERT(oneShot == incremental);
        });
}

/** Different inputs produce different digests (collision resistance sanity check)
 *  @generalizes SDV_CRYPT_EAL_SM3_API_TC001 sensitivity test */
void test_different_inputs_different_digests() {
    rc::check("Different inputs produce different digests",
        []() {
            auto alg = genAlg();

            auto data1 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            auto data2 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());

            RC_PRE(data1 != data2);

            auto computeDigest = [&](const std::vector<uint8_t> &data) -> std::vector<uint8_t> {
                CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
                RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                std::vector<uint8_t> out(alg.digestSize);
                uint32_t outLen = alg.digestSize;
                RC_PRE(CRYPT_EAL_MdFinal(ctx, out.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MdFreeCtx(ctx);
                return out;
            };

            RC_ASSERT(computeDigest(data1) != computeDigest(data2));
        });
}

/** DupCtx produces same result as original
 *  @generalizes SDV_CRYPT_EAL_SM3_API_TC005 */
void test_dup_ctx() {
    rc::check("CRYPT_EAL_MdDupCtx produces same final digest as original",
        []() {
            auto alg = genAlg();

            auto prefix = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());
            auto suffix = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());

            CRYPT_EAL_MdCtx *orig = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(orig != nullptr);
            RC_PRE(CRYPT_EAL_MdInit(orig) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MdUpdate(orig, prefix.data(), prefix.size()) == CRYPT_SUCCESS);

            // Dup mid-stream
            CRYPT_EAL_MdCtx *dup = CRYPT_EAL_MdDupCtx(orig);
            RC_PRE(dup != nullptr);

            // Continue both with same suffix
            RC_PRE(CRYPT_EAL_MdUpdate(orig, suffix.data(), suffix.size()) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MdUpdate(dup,  suffix.data(), suffix.size()) == CRYPT_SUCCESS);

            std::vector<uint8_t> outOrig(alg.digestSize), outDup(alg.digestSize);
            uint32_t lenOrig = alg.digestSize, lenDup = alg.digestSize;
            RC_PRE(CRYPT_EAL_MdFinal(orig, outOrig.data(), &lenOrig) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MdFinal(dup,  outDup.data(),  &lenDup)  == CRYPT_SUCCESS);

            CRYPT_EAL_MdFreeCtx(orig);
            CRYPT_EAL_MdFreeCtx(dup);

            RC_ASSERT(outOrig == outDup);
        });
}

/** Reinit resets the state, allowing reuse
 *  @generalizes SDV_CRYPT_EAL_SHA2_API_TC001 Deinit+Init pattern */
void test_reinit_reuse() {
    rc::check("CRYPT_EAL_MdInit after Final resets state for reuse",
        []() {
            auto alg = genAlg();

            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 64), gen::arbitrary<uint8_t>());

            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);

            // First run
            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            std::vector<uint8_t> out1(alg.digestSize);
            uint32_t len1 = alg.digestSize;
            RC_PRE(CRYPT_EAL_MdFinal(ctx, out1.data(), &len1) == CRYPT_SUCCESS);

            // Re-init and second run with same data
            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
            std::vector<uint8_t> out2(alg.digestSize);
            uint32_t len2 = alg.digestSize;
            RC_PRE(CRYPT_EAL_MdFinal(ctx, out2.data(), &len2) == CRYPT_SUCCESS);

            CRYPT_EAL_MdFreeCtx(ctx);

            // Must produce the same digest
            RC_ASSERT(out1 == out2);
        });
}

/** One-shot CRYPT_EAL_Md matches multi-step */
void test_oneshot_api() {
    rc::check("CRYPT_EAL_Md one-shot matches multi-step Init+Update+Final",
        []() {
            auto alg = genAlg();
            auto data = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(0, 256), gen::arbitrary<uint8_t>());

            // Multi-step
            std::vector<uint8_t> multiOut(alg.digestSize);
            {
                CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
                RC_PRE(ctx != nullptr);
                RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);
                if (!data.empty()) {
                    RC_PRE(CRYPT_EAL_MdUpdate(ctx, data.data(), data.size()) == CRYPT_SUCCESS);
                }
                uint32_t outLen = alg.digestSize;
                RC_PRE(CRYPT_EAL_MdFinal(ctx, multiOut.data(), &outLen) == CRYPT_SUCCESS);
                CRYPT_EAL_MdFreeCtx(ctx);
            }

            // One-shot
            std::vector<uint8_t> oneShotOut(alg.digestSize);
            uint32_t oneShotLen = alg.digestSize;
            int32_t ret = CRYPT_EAL_Md(alg.id,
                data.empty() ? nullptr : data.data(), data.size(),
                oneShotOut.data(), &oneShotLen);
            RC_PRE(ret == CRYPT_SUCCESS);

            RC_ASSERT(multiOut == oneShotOut);
        });
}

/** Zero-length Update succeeds */
void test_zero_len_update() {
    rc::check("CRYPT_EAL_MdUpdate with zero length succeeds",
        []() {
            auto alg = genAlg();
            CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(alg.id);
            RC_PRE(ctx != nullptr);
            RC_PRE(CRYPT_EAL_MdInit(ctx) == CRYPT_SUCCESS);

            // Update with 0 bytes using a non-null pointer
            uint8_t dummy = 0;
            int32_t ret = CRYPT_EAL_MdUpdate(ctx, &dummy, 0);
            RC_ASSERT(ret == CRYPT_SUCCESS);

            CRYPT_EAL_MdFreeCtx(ctx);
        });
}

// ---------------------------------------------------------------------------
// Registry + main
// ---------------------------------------------------------------------------

std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx_update",                 test_null_ctx_update},
    {"null_ctx_final",                  test_null_ctx_final},
    {"update_before_init",              test_update_before_init},
    {"final_before_init",               test_final_before_init},
    {"update_after_final",              test_update_after_final},
    {"final_after_final",               test_final_after_final},
    {"output_length",                   test_output_length},
    {"get_digest_size",                 test_get_digest_size},
    {"determinism",                     test_determinism},
    {"incremental_equals_oneshot",      test_incremental_equals_oneshot},
    {"different_inputs_different_digests", test_different_inputs_different_digests},
    {"dup_ctx",                         test_dup_ctx},
    {"reinit_reuse",                    test_reinit_reuse},
    {"oneshot_api",                     test_oneshot_api},
    {"zero_len_update",                 test_zero_len_update},
};

void printUsage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--list|-l] [--help|-h] [TEST_NAMES...]\n"
              << "  " << prog << "                   # Run all tests\n"
              << "  " << prog << " --list            # List test names\n"
              << "  " << prog << " determinism       # Run one test\n";
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
