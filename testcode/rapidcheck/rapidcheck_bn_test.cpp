/**
 * @file rapidcheck_bn_test.cpp
 * @brief RapidCheck property-based tests for BN (BigNum) API
 *
 * Generalizes unit tests from:
 *   testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
 *
 * Usage:
 *   ./rapidcheck_bn_test              # Run all tests
 *   ./rapidcheck_bn_test --list       # List all test names
 *   ./rapidcheck_bn_test test1 test2  # Run specific tests
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

static const int BN_TEST_MAX_BITS = 2048;

BN_BigNum *createRandomBn(uint32_t bits) {
    BN_BigNum *bn = BN_Create(bits);
    if (bn == nullptr) return nullptr;
    
    uint32_t bytes = (bits + 7) / 8;
    std::vector<uint8_t> data(bytes);
    for (auto &b : data) {
        b = *gen::arbitrary<uint8_t>();
    }
    
    if (BN_Bin2Bn(bn, data.data(), bytes) != CRYPT_SUCCESS) {
        BN_Destroy(bn);
        return nullptr;
    }
    return bn;
}

void test_bn_create_destroy() {
    rc::check("BN_Create and BN_Destroy work correctly",
        []() {
            auto bits = *gen::inRange(0, BN_TEST_MAX_BITS);
            BN_BigNum *bn = BN_Create(bits);
            RC_ASSERT(bn != nullptr);
            BN_Destroy(bn);
        });
}

void test_bn_create_max_bits() {
    rc::check("BN_Create fails for bits > BN_MAX_BITS",
        []() {
            BN_BigNum *bn = BN_Create((1u << 29) + 1);
            RC_ASSERT(bn == nullptr);
        });
}

void test_bn_set_limb() {
    rc::check("BN_SetLimb sets correct value",
        []() {
            BN_BigNum *bn = BN_Create(64);
            RC_PRE(bn != nullptr);
            
            auto val = *gen::arbitrary<uint64_t>();
            int32_t ret = BN_SetLimb(bn, val);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            BN_Destroy(bn);
        });
}

void test_bn_copy() {
    rc::check("BN_Copy creates exact copy",
        []() {
            auto bits = *gen::inRange(64, BN_TEST_MAX_BITS);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *r = BN_Create(bits);
            RC_PRE(r != nullptr);
            
            int32_t ret = BN_Copy(r, a);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_Compare(a, r) == 0);
            
            BN_Destroy(a);
            BN_Destroy(r);
        });
}

void test_bn_copy_null() {
    rc::check("BN_Copy returns CRYPT_NULL_INPUT for null params",
        []() {
            int32_t ret = BN_Copy(nullptr, nullptr);
            RC_ASSERT(ret == CRYPT_NULL_INPUT);
        });
}

void test_bn_compare_symmetric() {
    rc::check("BN_Compare is symmetric (a==b implies b==a)",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *b = BN_Create(bits);
            RC_PRE(b != nullptr);
            
            RC_PRE(BN_Copy(b, a) == CRYPT_SUCCESS);
            
            int cmp1 = BN_Compare(a, b);
            int cmp2 = BN_Compare(b, a);
            RC_ASSERT(cmp1 == 0 && cmp2 == 0);
            
            BN_Destroy(a);
            BN_Destroy(b);
        });
}

void test_bn_compare_transitive() {
    rc::check("BN_Compare is transitive for equal values",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *b = BN_Create(bits);
            BN_BigNum *c = BN_Create(bits);
            RC_PRE(b != nullptr && c != nullptr);
            
            RC_PRE(BN_Copy(b, a) == CRYPT_SUCCESS);
            RC_PRE(BN_Copy(c, b) == CRYPT_SUCCESS);
            
            RC_ASSERT(BN_Compare(a, c) == 0);
            
            BN_Destroy(a);
            BN_Destroy(b);
            BN_Destroy(c);
        });
}

void test_bn_add_zero() {
    rc::check("BN_Add with zero leaves value unchanged",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *zero = BN_Create(64);
            BN_BigNum *r = BN_Create(bits + 64);
            RC_PRE(zero != nullptr && r != nullptr);
            
            RC_PRE(BN_SetLimb(zero, 0) == CRYPT_SUCCESS);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits);
            RC_PRE(opt != nullptr);
            
            int32_t ret = BN_Add(r, a, zero, opt);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_Compare(r, a) == 0);
            
            BN_Destroy(a);
            BN_Destroy(zero);
            BN_Destroy(r);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_add_commutative() {
    rc::check("BN_Add is commutative (a+b == b+a)",
        []() {
            auto bits = *gen::inRange(64, 256);
            BN_BigNum *a = createRandomBn(bits);
            BN_BigNum *b = createRandomBn(bits);
            RC_PRE(a != nullptr && b != nullptr);
            
            BN_BigNum *r1 = BN_Create(bits * 2);
            BN_BigNum *r2 = BN_Create(bits * 2);
            RC_PRE(r1 != nullptr && r2 != nullptr);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits * 2);
            RC_PRE(opt != nullptr);
            
            RC_PRE(BN_Add(r1, a, b, opt) == CRYPT_SUCCESS);
            RC_PRE(BN_Add(r2, b, a, opt) == CRYPT_SUCCESS);
            
            RC_ASSERT(BN_Compare(r1, r2) == 0);
            
            BN_Destroy(a);
            BN_Destroy(b);
            BN_Destroy(r1);
            BN_Destroy(r2);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_sub_zero() {
    rc::check("BN_Sub with zero leaves value unchanged",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *zero = BN_Create(64);
            BN_BigNum *r = BN_Create(bits);
            RC_PRE(zero != nullptr && r != nullptr);
            
            RC_PRE(BN_SetLimb(zero, 0) == CRYPT_SUCCESS);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits);
            RC_PRE(opt != nullptr);
            
            int32_t ret = BN_Sub(r, a, zero, opt);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_Compare(r, a) == 0);
            
            BN_Destroy(a);
            BN_Destroy(zero);
            BN_Destroy(r);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_sub_self() {
    rc::check("BN_Sub(a, a) == 0",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *r = BN_Create(bits);
            RC_PRE(r != nullptr);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits);
            RC_PRE(opt != nullptr);
            
            int32_t ret = BN_Sub(r, a, a, opt);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_IsZero(r));
            
            BN_Destroy(a);
            BN_Destroy(r);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_mul_one() {
    rc::check("BN_Mul by one leaves value unchanged",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *one = BN_Create(64);
            BN_BigNum *r = BN_Create(bits * 2);
            RC_PRE(one != nullptr && r != nullptr);
            
            RC_PRE(BN_SetLimb(one, 1) == CRYPT_SUCCESS);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits * 2);
            RC_PRE(opt != nullptr);
            
            int32_t ret = BN_Mul(r, a, one, opt);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_Compare(r, a) == 0);
            
            BN_Destroy(a);
            BN_Destroy(one);
            BN_Destroy(r);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_mul_zero() {
    rc::check("BN_Mul by zero yields zero",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            BN_BigNum *zero = BN_Create(64);
            BN_BigNum *r = BN_Create(bits * 2);
            RC_PRE(zero != nullptr && r != nullptr);
            
            RC_PRE(BN_SetLimb(zero, 0) == CRYPT_SUCCESS);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits * 2);
            RC_PRE(opt != nullptr);
            
            int32_t ret = BN_Mul(r, a, zero, opt);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_IsZero(r));
            
            BN_Destroy(a);
            BN_Destroy(zero);
            BN_Destroy(r);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_mul_commutative() {
    rc::check("BN_Mul is commutative (a*b == b*a)",
        []() {
            auto bits = *gen::inRange(64, 256);
            BN_BigNum *a = createRandomBn(bits);
            BN_BigNum *b = createRandomBn(bits);
            RC_PRE(a != nullptr && b != nullptr);
            
            BN_BigNum *r1 = BN_Create(bits * 2);
            BN_BigNum *r2 = BN_Create(bits * 2);
            RC_PRE(r1 != nullptr && r2 != nullptr);
            
            BN_Optimizer *opt = BN_OptimizerCreate(bits * 2);
            RC_PRE(opt != nullptr);
            
            RC_PRE(BN_Mul(r1, a, b, opt) == CRYPT_SUCCESS);
            RC_PRE(BN_Mul(r2, b, a, opt) == CRYPT_SUCCESS);
            
            RC_ASSERT(BN_Compare(r1, r2) == 0);
            
            BN_Destroy(a);
            BN_Destroy(b);
            BN_Destroy(r1);
            BN_Destroy(r2);
            BN_OptimizerDestroy(opt);
        });
}

void test_bn_bin2bn_bn2bin_roundtrip() {
    rc::check("BN_Bin2Bn and BN_Bn2Bin are inverses",
        []() {
            auto len = *gen::inRange(1, 128);
            auto data = *gen::container<std::vector<uint8_t>>(len, gen::arbitrary<uint8_t>());
            
            BN_BigNum *bn = BN_Create(len * 8);
            RC_PRE(bn != nullptr);
            
            int32_t ret = BN_Bin2Bn(bn, data.data(), data.size());
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> out(len + 8);
            uint32_t outLen = out.size();
            ret = BN_Bn2Bin(bn, out.data(), &outLen, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> trimmed(out.begin(), out.begin() + outLen);
            
            BN_BigNum *bn2 = BN_Create(len * 8);
            RC_PRE(bn2 != nullptr);
            ret = BN_Bin2Bn(bn2, trimmed.data(), trimmed.size());
            RC_PRE(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(BN_Compare(bn, bn2) == 0);
            
            BN_Destroy(bn);
            BN_Destroy(bn2);
        });
}

void test_bn_is_zero() {
    rc::check("BN_IsZero correctly identifies zero",
        []() {
            BN_BigNum *zero = BN_Create(64);
            RC_PRE(zero != nullptr);
            RC_PRE(BN_SetLimb(zero, 0) == CRYPT_SUCCESS);
            
            RC_ASSERT(BN_IsZero(zero));
            
            BN_BigNum *nonzero = BN_Create(64);
            RC_PRE(nonzero != nullptr);
            RC_PRE(BN_SetLimb(nonzero, 1) == CRYPT_SUCCESS);
            
            RC_ASSERT(!BN_IsZero(nonzero));
            
            BN_Destroy(zero);
            BN_Destroy(nonzero);
        });
}

void test_bn_bits_consistency() {
    rc::check("BN_Bits returns consistent value",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            uint32_t bits1 = BN_Bits(a);
            uint32_t bits2 = BN_Bits(a);
            RC_ASSERT(bits1 == bits2);
            
            BN_Destroy(a);
        });
}

void test_bn_bytes_consistency() {
    rc::check("BN_Bytes returns consistent value",
        []() {
            auto bits = *gen::inRange(64, 512);
            BN_BigNum *a = createRandomBn(bits);
            RC_PRE(a != nullptr);
            
            uint32_t bytes1 = BN_Bytes(a);
            uint32_t bytes2 = BN_Bytes(a);
            RC_ASSERT(bytes1 == bytes2);
            
            BN_Destroy(a);
        });
}

std::map<std::string, std::function<void()>> testRegistry = {
    {"bn_create_destroy", test_bn_create_destroy},
    {"bn_create_max_bits", test_bn_create_max_bits},
    {"bn_set_limb", test_bn_set_limb},
    {"bn_copy", test_bn_copy},
    {"bn_copy_null", test_bn_copy_null},
    {"bn_compare_symmetric", test_bn_compare_symmetric},
    {"bn_compare_transitive", test_bn_compare_transitive},
    {"bn_add_zero", test_bn_add_zero},
    {"bn_add_commutative", test_bn_add_commutative},
    {"bn_sub_zero", test_bn_sub_zero},
    {"bn_sub_self", test_bn_sub_self},
    {"bn_mul_one", test_bn_mul_one},
    {"bn_mul_zero", test_bn_mul_zero},
    {"bn_mul_commutative", test_bn_mul_commutative},
    {"bn_bin2bn_bn2bin_roundtrip", test_bn_bin2bn_bn2bin_roundtrip},
    {"bn_is_zero", test_bn_is_zero},
    {"bn_bits_consistency", test_bn_bits_consistency},
    {"bn_bytes_consistency", test_bn_bytes_consistency},
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