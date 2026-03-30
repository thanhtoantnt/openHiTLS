/**
 * @file rapidcheck_base64_test.cpp
 * @brief RapidCheck property-based tests for Base64 encoding/decoding
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "bsl_base64.h"
#include "bsl_errno.h"

using namespace rc;

int main() {
    /**
     * @test Base64 encode-decode roundtrip
     * @property decode(encode(data)) == data
     * @generalizes SDV_CRYPTO_BASE64_API_TC001 - Encode/decode tests
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c:226-250
     */
    rc::check("Base64 encode-decode roundtrip",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 1024);
            
            uint32_t encLen = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded(encLen);
            
            int32_t ret = BSL_BASE64_Encode(input.data(), input.size(), encoded.data(), &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            uint32_t decLen = input.size() + 1;
            std::vector<uint8_t> decoded(decLen);
            
            ret = BSL_BASE64_Decode(encoded.data(), encLen, decoded.data(), &decLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(decLen == input.size());
            RC_ASSERT(std::memcmp(input.data(), decoded.data(), input.size()) == 0);
        });

    /**
     * @test Base64 output size follows encoding rules
     * @property For input of length n, output length is ceil(n/3)*4
     * @generalizes SDV_CRYPTO_BASE64_API_TC002 - Output length test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c:231-233
     */
    rc::check("Base64 output size follows encoding rules",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() <= 1024);
            
            uint32_t expectedLen = ((input.size() + 2) / 3) * 4;
            uint32_t encLen = expectedLen + 100;
            std::vector<char> encoded(encLen);
            
            int32_t ret = BSL_BASE64_Encode(input.data(), input.size(), encoded.data(), &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(encLen == expectedLen);
        });

    /**
     * @test Base64 encoding is deterministic
     * @property encode(data) == encode(data)
     * @generalizes Determinism test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
     */
    rc::check("Base64 encoding is deterministic",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t encLen = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded1(encLen);
            std::vector<char> encoded2(encLen);
            
            BSL_BASE64_Encode(input.data(), input.size(), encoded1.data(), &encLen);
            BSL_BASE64_Encode(input.data(), input.size(), encoded2.data(), &encLen);
            
            RC_ASSERT(std::strcmp(encoded1.data(), encoded2.data()) == 0);
        });

    /**
     * @test Base64 produces valid characters
     * @property Output contains only A-Z, a-z, 0-9, +, /, =
     * @generalizes Output format validation
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
     */
    rc::check("Base64 produces valid characters",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t encLen = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded(encLen);
            
            int32_t ret = BSL_BASE64_Encode(input.data(), input.size(), encoded.data(), &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            for (uint32_t i = 0; i < encLen; i++) {
                char c = encoded[i];
                bool valid = (c >= 'A' && c <= 'Z') ||
                             (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') ||
                             c == '+' || c == '/' || c == '=';
                RC_ASSERT(valid);
            }
        });

    /**
     * @test Base64 different inputs produce different outputs
     * @property For distinct inputs, encode(a) != encode(b)
     * @generalizes Collision resistance test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
     */
    rc::check("Base64 different inputs produce different outputs",
        [](const std::vector<uint8_t> &input1, const std::vector<uint8_t> &input2) {
            RC_PRE(input1 != input2);
            RC_PRE(input1.size() > 0 && input1.size() <= 256);
            RC_PRE(input2.size() > 0 && input2.size() <= 256);
            
            uint32_t encLen1 = ((input1.size() + 2) / 3) * 4 + 1;
            uint32_t encLen2 = ((input2.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded1(encLen1);
            std::vector<char> encoded2(encLen2);
            
            BSL_BASE64_Encode(input1.data(), input1.size(), encoded1.data(), &encLen1);
            BSL_BASE64_Encode(input2.data(), input2.size(), encoded2.data(), &encLen2);
            
            if (input1.size() == input2.size()) {
                RC_ASSERT(std::strcmp(encoded1.data(), encoded2.data()) != 0);
            }
        });

    /**
     * @test Base64 empty input handling
     * @property Empty input produces empty output
     * @generalizes Edge case test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
     */
    rc::check("Base64 empty input produces empty output",
        []() {
            uint8_t empty[1] = {0};
            uint32_t encLen = 100;
            char encoded[100];
            
            int32_t ret = BSL_BASE64_Encode(empty, 0, encoded, &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(encLen == 0);
        });

    /**
     * @test Base64 padding for non-multiple of 3
     * @property Input length not divisible by 3 produces padding
     * @generalizes Padding test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c:30-50
     */
    rc::check("Base64 padding for non-multiple of 3 input",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            RC_PRE(input.size() % 3 != 0);
            
            uint32_t encLen = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded(encLen);
            
            int32_t ret = BSL_BASE64_Encode(input.data(), input.size(), encoded.data(), &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            size_t paddingCount = 0;
            for (uint32_t i = 0; i < encLen; i++) {
                if (encoded[i] == '=') paddingCount++;
            }
            
            uint32_t remainder = input.size() % 3;
            RC_ASSERT(paddingCount == (3 - remainder));
        });

    /**
     * @test Base64 no padding for multiple of 3
     * @property Input length divisible by 3 produces no padding
     * @generalizes No padding test
     * @see testcode/sdv/testcase/bsl/base64/test_suite_sdv_base64.c
     */
    rc::check("Base64 no padding for multiple of 3 input",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            RC_PRE(input.size() % 3 == 0);
            
            uint32_t encLen = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> encoded(encLen);
            
            int32_t ret = BSL_BASE64_Encode(input.data(), input.size(), encoded.data(), &encLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            for (uint32_t i = 0; i < encLen; i++) {
                RC_ASSERT(encoded[i] != '=');
            }
        });

    return 0;
}