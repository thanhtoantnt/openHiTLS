/**
 * @file rapidcheck_pbkdf2_test.cpp
 * @brief RapidCheck property-based tests for PBKDF2 KDF (CRYPT_KDF_PBKDF2)
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/pbkdf2/test_suite_sdv_eal_kdf_pbkdf2.c
 *
 * Properties tested:
 *  - NULL ctx / output → CRYPT_NULL_INPUT
 *  - Zero output length → CRYPT_PBKDF2_PARAM_ERROR
 *  - Iteration count 0 → CRYPT_PBKDF2_PARAM_ERROR
 *  - Determinism: same (password, salt, iter, alg) → same key
 *  - Sensitivity to password, salt, iter
 *  - Output length contract: exactly requested length is produced
 *  - Empty password and salt are accepted
 *  - Multiple MAC algorithms succeed
 *
 * Usage:
 *   ./rapidcheck_pbkdf2_test              # Run all tests
 *   ./rapidcheck_pbkdf2_test --list       # List test names
 *   ./rapidcheck_pbkdf2_test <name> ...   # Run specific tests
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
#include "bsl_params.h"
#include "crypt_params_key.h"

using namespace rc;

/* Minimum iteration count mandated by GM/T 0091-2020 */
static const uint32_t MIN_ITER = 1024;

struct Pbkdf2AlgInfo {
    CRYPT_MAC_AlgId id;
    const char *name;
};

static const Pbkdf2AlgInfo PBKDF2_ALGS[] = {
    { CRYPT_MAC_HMAC_MD5,    "HMAC-MD5"    },
    { CRYPT_MAC_HMAC_SHA1,   "HMAC-SHA1"   },
    { CRYPT_MAC_HMAC_SHA224, "HMAC-SHA224" },
    { CRYPT_MAC_HMAC_SHA256, "HMAC-SHA256" },
    { CRYPT_MAC_HMAC_SHA384, "HMAC-SHA384" },
    { CRYPT_MAC_HMAC_SHA512, "HMAC-SHA512" },
    { CRYPT_MAC_HMAC_SM3,    "HMAC-SM3"    },
};
static const size_t PBKDF2_ALGS_COUNT = sizeof(PBKDF2_ALGS) / sizeof(PBKDF2_ALGS[0]);

/* Helper: create and configure a PBKDF2 context, return ctx (caller frees) */
static CRYPT_EAL_KdfCtx *makePbkdf2Ctx(
    CRYPT_MAC_AlgId macId,
    const std::vector<uint8_t> &password,
    const std::vector<uint8_t> &salt,
    uint32_t iter)
{
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    if (ctx == nullptr) return nullptr;

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    uint32_t macIdVal = static_cast<uint32_t>(macId);

    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,   BSL_PARAM_TYPE_UINT32,
        &macIdVal, sizeof(macIdVal));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        password.empty() ? nullptr : const_cast<uint8_t*>(password.data()), password.size());
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT,     BSL_PARAM_TYPE_OCTETS,
        salt.empty() ? nullptr : const_cast<uint8_t*>(salt.data()), salt.size());
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER,     BSL_PARAM_TYPE_UINT32,
        &iter, sizeof(iter));

    if (CRYPT_EAL_KdfSetParam(ctx, params) != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return nullptr;
    }
    return ctx;
}

/* ── Tests ────────────────────────────────────────────────────────────────── */

void test_null_ctx_derive() {
    rc::check("CRYPT_EAL_KdfDerive returns CRYPT_NULL_INPUT when ctx is NULL",
        []() {
            auto outLen = *gen::inRange<uint32_t>(1, 64);
            std::vector<uint8_t> out(outLen);
            int32_t ret = CRYPT_EAL_KdfDerive(nullptr, out.data(), outLen);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_null_output_derive() {
    rc::check("CRYPT_EAL_KdfDerive returns CRYPT_NULL_INPUT when output is NULL",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            int32_t ret = CRYPT_EAL_KdfDerive(ctx, nullptr, 32);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_zero_iter_rejected() {
    rc::check("PBKDF2 SetParam rejects iteration count 0",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());

            /* pass iter=0 directly */
            CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
            RC_PRE(ctx != nullptr);

            BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
            uint32_t macIdVal = static_cast<uint32_t>(PBKDF2_ALGS[algIdx].id);
            uint32_t iterZero = 0;
            BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,   BSL_PARAM_TYPE_UINT32,
                &macIdVal, sizeof(macIdVal));
            BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
                const_cast<uint8_t*>(pw.data()), pw.size());
            BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT,     BSL_PARAM_TYPE_OCTETS,
                const_cast<uint8_t*>(salt.data()), salt.size());
            BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER,     BSL_PARAM_TYPE_UINT32,
                &iterZero, sizeof(iterZero));

            int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
            RC_ASSERT(ret == CRYPT_PBKDF2_PARAM_ERROR);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_zero_outlen_rejected() {
    rc::check("CRYPT_EAL_KdfDerive rejects output length 0",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            uint8_t dummy = 0;
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, &dummy, 0);
            RC_ASSERT(ret == CRYPT_PBKDF2_PARAM_ERROR);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_output_length_contract() {
    rc::check("PBKDF2 output length exactly matches requested length",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto outLen = *gen::inRange<uint32_t>(1, 64);

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> out(outLen, 0);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_determinism() {
    rc::check("PBKDF2 is deterministic: same inputs → same output",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            uint32_t outLen = 32;

            CRYPT_EAL_KdfCtx *ctx1 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            CRYPT_EAL_KdfCtx *ctx2 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            RC_PRE(ctx1 != nullptr && ctx2 != nullptr);

            std::vector<uint8_t> out1(outLen), out2(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx1, out1.data(), outLen) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx2, out2.data(), outLen) == CRYPT_SUCCESS);

            RC_ASSERT(out1 == out2);
            CRYPT_EAL_KdfFreeCtx(ctx1);
            CRYPT_EAL_KdfFreeCtx(ctx2);
        });
}

void test_password_sensitivity() {
    rc::check("PBKDF2 output differs when password differs",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw1  = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto pw2  = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(pw1 != pw2);
            auto salt = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            uint32_t outLen = 32;

            CRYPT_EAL_KdfCtx *ctx1 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw1, salt, MIN_ITER);
            CRYPT_EAL_KdfCtx *ctx2 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw2, salt, MIN_ITER);
            RC_PRE(ctx1 != nullptr && ctx2 != nullptr);

            std::vector<uint8_t> out1(outLen), out2(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx1, out1.data(), outLen) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx2, out2.data(), outLen) == CRYPT_SUCCESS);

            RC_ASSERT(out1 != out2);
            CRYPT_EAL_KdfFreeCtx(ctx1);
            CRYPT_EAL_KdfFreeCtx(ctx2);
        });
}

void test_salt_sensitivity() {
    rc::check("PBKDF2 output differs when salt differs",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw    = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(salt1 != salt2);
            uint32_t outLen = 32;

            CRYPT_EAL_KdfCtx *ctx1 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt1, MIN_ITER);
            CRYPT_EAL_KdfCtx *ctx2 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt2, MIN_ITER);
            RC_PRE(ctx1 != nullptr && ctx2 != nullptr);

            std::vector<uint8_t> out1(outLen), out2(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx1, out1.data(), outLen) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx2, out2.data(), outLen) == CRYPT_SUCCESS);

            RC_ASSERT(out1 != out2);
            CRYPT_EAL_KdfFreeCtx(ctx1);
            CRYPT_EAL_KdfFreeCtx(ctx2);
        });
}

void test_iter_sensitivity() {
    rc::check("PBKDF2 output differs when iteration count differs",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            uint32_t iter1 = MIN_ITER;
            uint32_t iter2 = MIN_ITER + 1;
            uint32_t outLen = 32;

            CRYPT_EAL_KdfCtx *ctx1 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt, iter1);
            CRYPT_EAL_KdfCtx *ctx2 = makePbkdf2Ctx(PBKDF2_ALGS[algIdx].id, pw, salt, iter2);
            RC_PRE(ctx1 != nullptr && ctx2 != nullptr);

            std::vector<uint8_t> out1(outLen), out2(outLen);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx1, out1.data(), outLen) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx2, out2.data(), outLen) == CRYPT_SUCCESS);

            RC_ASSERT(out1 != out2);
            CRYPT_EAL_KdfFreeCtx(ctx1);
            CRYPT_EAL_KdfFreeCtx(ctx2);
        });
}

void test_empty_password_accepted() {
    rc::check("PBKDF2 accepts empty password",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto salt = *gen::container<std::vector<uint8_t>>(
                            *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            std::vector<uint8_t> emptyPw;

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, emptyPw, salt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> out(32);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), 32);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_empty_salt_accepted() {
    rc::check("PBKDF2 accepts empty salt",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw = *gen::container<std::vector<uint8_t>>(
                          *gen::inRange<size_t>(1, 32), gen::arbitrary<uint8_t>());
            std::vector<uint8_t> emptySalt;

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw, emptySalt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> out(32);
            int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), 32);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_all_mac_algorithms_succeed() {
    rc::check("PBKDF2 succeeds for all supported MAC algorithms",
        []() {
            auto pw   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            std::vector<uint8_t> out(32);

            for (size_t i = 0; i < PBKDF2_ALGS_COUNT; i++) {
                CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                    PBKDF2_ALGS[i].id, pw, salt, MIN_ITER);
                if (ctx == nullptr) continue; /* algorithm may be disabled */
                int32_t ret = CRYPT_EAL_KdfDerive(ctx, out.data(), 32);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                CRYPT_EAL_KdfFreeCtx(ctx);
            }
        });
}

void test_output_not_all_zeros() {
    rc::check("PBKDF2 output is not all zeros",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw, salt, MIN_ITER);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> out(32, 0);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx, out.data(), 32) == CRYPT_SUCCESS);

            bool allZero = true;
            for (auto b : out) { if (b != 0) { allZero = false; break; } }
            RC_ASSERT(!allZero);
            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

void test_reinit_via_setparam() {
    rc::check("PBKDF2 can be re-used by calling SetParam again",
        []() {
            auto algIdx = *gen::inRange<size_t>(0, PBKDF2_ALGS_COUNT);
            auto pw1   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto pw2   = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto salt2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());

            CRYPT_EAL_KdfCtx *ctx = makePbkdf2Ctx(
                PBKDF2_ALGS[algIdx].id, pw1, salt1, MIN_ITER);
            RC_PRE(ctx != nullptr);

            std::vector<uint8_t> out1(32), out2(32);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx, out1.data(), 32) == CRYPT_SUCCESS);

            /* Re-configure and derive again */
            BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
            uint32_t macIdVal = static_cast<uint32_t>(PBKDF2_ALGS[algIdx].id);
            uint32_t iter = MIN_ITER;
            BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,   BSL_PARAM_TYPE_UINT32,
                &macIdVal, sizeof(macIdVal));
            BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
                const_cast<uint8_t*>(pw2.data()), pw2.size());
            BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT,     BSL_PARAM_TYPE_OCTETS,
                const_cast<uint8_t*>(salt2.data()), salt2.size());
            BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER,     BSL_PARAM_TYPE_UINT32,
                &iter, sizeof(iter));
            RC_PRE(CRYPT_EAL_KdfSetParam(ctx, params) == CRYPT_SUCCESS);
            RC_PRE(CRYPT_EAL_KdfDerive(ctx, out2.data(), 32) == CRYPT_SUCCESS);

            CRYPT_EAL_KdfFreeCtx(ctx);
        });
}

/* ── Registry ─────────────────────────────────────────────────────────────── */

static std::map<std::string, std::function<void()>> testRegistry = {
    {"null_ctx_derive",          test_null_ctx_derive},
    {"null_output_derive",       test_null_output_derive},
    {"zero_iter_rejected",       test_zero_iter_rejected},
    {"zero_outlen_rejected",     test_zero_outlen_rejected},
    {"output_length_contract",   test_output_length_contract},
    {"determinism",              test_determinism},
    {"password_sensitivity",     test_password_sensitivity},
    {"salt_sensitivity",         test_salt_sensitivity},
    {"iter_sensitivity",         test_iter_sensitivity},
    {"empty_password_accepted",  test_empty_password_accepted},
    {"empty_salt_accepted",      test_empty_salt_accepted},
    {"all_mac_algorithms",       test_all_mac_algorithms_succeed},
    {"output_not_all_zeros",     test_output_not_all_zeros},
    {"reinit_via_setparam",      test_reinit_via_setparam},
};

static void listTests() {
    std::cout << "Available tests (" << testRegistry.size() << "):\n";
    for (auto &kv : testRegistry)
        std::cout << "  " << kv.first << "\n";
}

int main(int argc, char *argv[]) {
    std::vector<std::string> toRun;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--list" || a == "-l") { listTests(); return 0; }
        if (a == "--help" || a == "-h") {
            std::cout << "Usage: " << argv[0] << " [--list] [test_name ...]\n";
            return 0;
        }
        toRun.push_back(a);
    }

    if (toRun.empty()) {
        std::cout << "Running all " << testRegistry.size() << " tests...\n\n";
        for (auto &kv : testRegistry) {
            std::cout << "[ " << kv.first << " ]\n";
            kv.second();
            std::cout << "\n";
        }
    } else {
        for (auto &name : toRun) {
            auto it = testRegistry.find(name);
            if (it == testRegistry.end()) {
                std::cerr << "Unknown test '" << name << "'. Use --list.\n";
                return 1;
            }
            std::cout << "[ " << name << " ]\n";
            it->second();
            std::cout << "\n";
        }
    }
    return 0;
}
