/**
 * @file rapidcheck_bn_test.cpp
 * @brief RapidCheck property-based tests for BigNum (BN) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
 *
 * Usage:
 *   ./rapidcheck_bn_test              # Run all tests
 *   ./rapidcheck_bn_test --list       # List all test names
 *   ./rapidcheck_bn_test determinism  # Run specific test
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include "hitls_build.h"
#include "crypt_bn.h"
#include "crypt_errno.h"

using namespace rc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a random BN_UINT (valid limb value) */
BN_UINT genLimb() {
    return *gen::inRange<BN_UINT>(0, BN_UINT(100000));
}

/** Create a BN initialized with a random limb value, or with 0 if not set */
static BN_BigNum *genBn() {
    BN_BigNum *bn = BN_Create(64);
    if (bn) { BN_SetLimb(bn, genLimb()); }
    return bn;
}

// ---------------------------------------------------------------------------
// Test: Determinism — same inputs produce same results
// ---------------------------------------------------------------------------
void test_determinism() {
    rc::check("BN_Add is deterministic for same inputs",
        []() {
            auto a = genBn(); auto b = genBn();
            auto r1 = BN_Create(64); auto r2 = BN_Create(64);
            RC_PRE(a && b && r1 && r2);
            RC_ASSERT(BN_Add(r1, a, b) == CRYPT_SUCCESS);
            RC_ASSERT(BN_Add(r2, a, b) == CRYPT_SUCCESS);
            RC_ASSERT(BN_Cmp(r1, r2) == 0);
            BN_Destroy(a); BN_Destroy(b);
            BN_Destroy(r1); BN_Destroy(r2);
        });
}

// ---------------------------------------------------------------------------
// Test: SetLimb → GetLimb roundtrip
// ---------------------------------------------------------------------------
void test_set_limb_roundtrip() {
    rc::check("SetLimb then GetLimb returns original value",
        []() {
            BN_UINT v = genLimb();
            auto a = BN_Create(64);
            RC_PRE(a != nullptr);
            RC_ASSERT(BN_SetLimb(a, v) == CRYPT_SUCCESS);
            RC_ASSERT(BN_GetLimb(a) == v);
            BN_Destroy(a);
        });
}

// ---------------------------------------------------------------------------
// Test: Add commutativity — a + b == b + a
// ---------------------------------------------------------------------------
void test_add_commutative() {
    rc::check("a + b == b + a",
        []() {
            auto a = genBn(); auto b = genBn();
            auto r1 = BN_Create(64); auto r2 = BN_Create(64);
            RC_PRE(a && b && r1 && r2);
            RC_ASSERT(BN_Add(r1, a, b) == CRYPT_SUCCESS);
            RC_ASSERT(BN_Add(r2, b, a) == CRYPT_SUCCESS);
            RC_ASSERT(BN_Cmp(r1, r2) == 0);
            BN_Destroy(a); BN_Destroy(b);
            BN_Destroy(r1); BN_Destroy(r2);
        });
}

// ---------------------------------------------------------------------------
// Test: Add identity — a + 0 == a
// ---------------------------------------------------------------------------
void test_add_identity() {
    rc::check("a + 0 == a",
        []() {
            auto a = genBn();
            auto zero = BN_Create(64); BN_SetLimb(zero, 0);
            auto r = BN_Create(64);
            RC_PRE(a && zero && r);
            RC_ASSERT(BN_Add(r, a, zero) == CRYPT_SUCCESS);
            RC_ASSERT(BN_Cmp(r, a) == 0);
            BN_Destroy(a); BN_Destroy(zero); BN_Destroy(r);
        });
}

// ---------------------------------------------------------------------------
// Test: Sub self — a - a == 0
// ---------------------------------------------------------------------------
void test_sub_self() {
    rc::check("a - a == 0",
        []() {
            auto a = genBn();
            auto r = BN_Create(64);
            RC_PRE(a && r);
            RC_ASSERT(BN_Sub(r, a, a) == CRYPT_SUCCESS);
            RC_ASSERT(BN_IsZero(r));
            BN_Destroy(a); BN_Destroy(r);
        });
}

// ---------------------------------------------------------------------------
// Test: Mul by zero — a * 0 == 0
// ---------------------------------------------------------------------------
void test_mul_by_zero() {
    rc::check("a * 0 == 0",
        []() {
            auto a = genBn();
            auto zero = BN_Create(64); BN_SetLimb(zero, 0);
            auto r = BN_Create(64);
            auto opt = BN_OptimizerCreate();
            RC_PRE(a && zero && r && opt);
            RC_ASSERT(BN_Mul(r, a, zero, opt) == CRYPT_SUCCESS);
            RC_ASSERT(BN_IsZero(r));
            BN_OptimizerDestroy(opt);
            BN_Destroy(a); BN_Destroy(zero); BN_Destroy(r);
        });
}

// ---------------------------------------------------------------------------
// Test: Null inputs
// ---------------------------------------------------------------------------
void test_null_inputs() {
    rc::check("BN_Add returns CRYPT_NULL_INPUT when an input is NULL",
        []() {
            auto a = genBn();
            auto r = BN_Create(64);
            RC_PRE(a && r);
            RC_ASSERT(BN_Add(r, nullptr, a) == CRYPT_NULL_INPUT);
            RC_ASSERT(BN_Add(r, a, nullptr) == CRYPT_NULL_INPUT);
            BN_Destroy(a); BN_Destroy(r);
        });
}

// ---------------------------------------------------------------------------
// Test: Create + Destroy with various sizes
// ---------------------------------------------------------------------------
void test_create_destroy() {
    rc::check("create with various bit sizes does not crash",
        []() {
            uint32_t bits = *gen::inRange<uint32_t>(1, 4096);
            auto a = BN_Create(bits);
            RC_PRE(a != nullptr);
            BN_Destroy(a);
        });
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------
std::map<std::string, std::function<void()>> testRegistry = {
    {"determinism",        test_determinism},
    {"set_limb_roundtrip", test_set_limb_roundtrip},
    {"add_commutative",    test_add_commutative},
    {"add_identity",       test_add_identity},
    {"sub_self",           test_sub_self},
    {"mul_by_zero",        test_mul_by_zero},
    {"null_inputs",        test_null_inputs},
    {"create_destroy",     test_create_destroy},
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
    std::cout << "Big Num (BN) PBT — " __DATE__ " " __TIME__ "\n\n";
    std::vector<std::string> toRun;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--list" || a == "-l") { listTests(); return 0; }
        if (a == "--help" || a == "-h") { printUsage(argv[0]); return 0; }
        toRun.push_back(a);
    }

    if (toRun.empty()) {
        for (auto &kv : testRegistry) {
            std::cout << "Running test: " << kv.first << "\n";
            kv.second();
            std::cout << "\n";
        }
    } else {
        for (auto &name : toRun) {
            auto it = testRegistry.find(name);
            if (it == testRegistry.end()) {
                std::cerr << "Error: Unknown test '" << name << "'\n";
                return 1;
            }
            std::cout << "Running test: " << name << "\n";
            it->second();
            std::cout << "\n";
        }
    }
    return 0;
}
