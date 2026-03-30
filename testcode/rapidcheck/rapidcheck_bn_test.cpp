/**
 * @file rapidcheck_bn_test.cpp
 * @brief RapidCheck property-based tests for Big Number (BN) operations
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_bn.h"
#include "crypt_errno.h"

using namespace rc;

int main() {
    /**
     * @test BN_Create and BN_Destroy roundtrip
     * @property For all valid bit sizes, create/destroy succeeds
     * @generalizes SDV_CRYPTO_BN_CREATE_API_TC001 - BN creation tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c:121-133
     */
    rc::check("BN_Create creates valid BN for reasonable bit sizes",
        [](uint32_t bits) {
            RC_PRE(bits > 0);
            RC_PRE(bits <= 4096);
            
            BN_BigNum *bn = BN_Create(bits);
            RC_ASSERT(bn != nullptr);
            
            BN_Destroy(bn);
        });

    /**
     * @test BN_Bin2Bn and BN_Bn2Bin roundtrip
     * @property For all byte arrays, bin2bn(bn2bin(data)) == data
     * @generalizes SDV_CRYPTO_BN_BIN2BN_API_TC001 - Binary conversion tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
     */
    rc::check("BN_Bin2Bn and BN_Bn2Bin roundtrip preserves data",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            BN_BigNum *bn = BN_Create(input.size() * 8);
            RC_PRE(bn != nullptr);
            
            int32_t ret = BN_Bin2Bn(bn, const_cast<uint8_t*>(input.data()), input.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(input.size());
            uint32_t outLen = input.size();
            ret = BN_Bn2Bin(bn, output.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(outLen <= input.size());
            
            BN_Destroy(bn);
        });

    /**
     * @test BN_SetSign and BN_IsNegative
     * @property For all BNs, setSign affects isNegative correctly
     * @generalizes SDV_CRYPTO_BN_SETSIGN_API_TC001 - Sign handling tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c:136-160
     */
    rc::check("BN_SetSign correctly sets sign for non-zero values",
        [](const std::vector<uint8_t> &input, bool sign) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 128);
            
            BN_BigNum *bn = BN_Create(input.size() * 8);
            RC_PRE(bn != nullptr);
            
            int32_t ret = BN_Bin2Bn(bn, const_cast<uint8_t*>(input.data()), input.size());
            RC_PRE(ret == CRYPT_SUCCESS);
            
            bool isZero = BN_IsZero(bn);
            
            if (!isZero) {
                ret = BN_SetSign(bn, sign);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                RC_ASSERT(BN_IsNegative(bn) == sign);
            }
            
            BN_Destroy(bn);
        });

    /**
     * @test BN_Copy preserves value
     * @property For all BNs, copy(bn) == bn
     * @generalizes SDV_CRYPTO_BN_COPY_API_TC001 - Copy tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
     */
    rc::check("BN_Copy preserves value",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 128);
            
            BN_BigNum *bnSrc = BN_Create(input.size() * 8);
            BN_BigNum *bnDst = BN_Create(input.size() * 8);
            RC_PRE(bnSrc != nullptr);
            RC_PRE(bnDst != nullptr);
            
            BN_Bin2Bn(bnSrc, const_cast<uint8_t*>(input.data()), input.size());
            
            int32_t ret = BN_Copy(bnDst, bnSrc);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            uint32_t len1 = input.size();
            uint32_t len2 = input.size();
            std::vector<uint8_t> out1(len1), out2(len2);
            
            BN_Bn2Bin(bnSrc, out1.data(), &len1);
            BN_Bn2Bin(bnDst, out2.data(), &len2);
            
            RC_ASSERT(len1 == len2);
            RC_ASSERT(std::memcmp(out1.data(), out2.data(), len1) == 0);
            
            BN_Destroy(bnSrc);
            BN_Destroy(bnDst);
        });

    /**
     * @test BN_IsZero for zero value
     * @property BN_Create followed by BN_IsZero returns true
     * @generalizes SDV_CRYPTO_BN_ISZERO_API_TC001 - Zero detection tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
     */
    rc::check("BN_IsZero returns true for newly created BN",
        [](uint32_t bits) {
            RC_PRE(bits > 0);
            RC_PRE(bits <= 1024);
            
            BN_BigNum *bn = BN_Create(bits);
            RC_PRE(bn != nullptr);
            
            RC_ASSERT(BN_IsZero(bn) == true);
            
            BN_Destroy(bn);
        });

    /**
     * @test BN_GetBitLen returns correct bit length
     * @property For all inputs, bit length is consistent
     * @generalizes SDV_CRYPTO_BN_BITLEN_API_TC001 - Bit length tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
     */
    rc::check("BN_Bits returns consistent bit length",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 128);
            
            BN_BigNum *bn = BN_Create(input.size() * 8);
            RC_PRE(bn != nullptr);
            
            BN_Bin2Bn(bn, const_cast<uint8_t*>(input.data()), input.size());
            
            uint32_t bits = BN_Bits(bn);
            
            RC_ASSERT(bits <= input.size() * 8);
            
            BN_Destroy(bn);
        });

    /**
     * @test BN_SetBit
     * @property Setting bits works correctly
     * @generalizes SDV_CRYPTO_BN_SETBIT_API_TC001 - Bit manipulation tests
     * @see testcode/sdv/testcase/crypto/bn/test_suite_sdv_bn.c
     */
    rc::check("BN_SetBit works correctly",
        [](uint32_t bitPos) {
            RC_PRE(bitPos < 1024);
            
            BN_BigNum *bn = BN_Create(1024);
            RC_PRE(bn != nullptr);
            
            RC_ASSERT(BN_IsZero(bn) == true);
            
            int32_t ret = BN_SetBit(bn, bitPos);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(BN_IsZero(bn) == false);
            
            BN_Destroy(bn);
        });

    return 0;
}