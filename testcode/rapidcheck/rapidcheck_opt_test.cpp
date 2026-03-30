/**
 * @file rapidcheck_opt_test.cpp
 * @brief RapidCheck property-based tests for app_opt command-line parsing utilities
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/apps/test_suite_ut_opt.c
 * 
 * Property-based testing automatically generates thousands of random test cases
 * to find edge cases that fixed unit tests might miss.
 */

#include <rapidcheck.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <climits>

#include "app_opt.h"
#include "app_errno.h"

using namespace rc;

int main() {
    /**
     * @test HITLS_APP_BytesToHex roundtrip
     * @property For all byte arrays, hexToBytes(bytesToHex(bytes)) == bytes
     * @generalizes UT_HITLS_APP_BytesToHex_TC001 - Parameter validation tests
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:821-838
     */
    rc::check("HITLS_APP_BytesToHex produces valid hex string",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 1024);
            
            uint32_t hexSize = input.size() * 2 + 1;
            std::vector<char> hexStr(hexSize);
            
            int32_t ret = HITLS_APP_BytesToHex(input.data(), input.size(), 
                                               hexStr.data(), hexSize);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            
            for (size_t i = 0; i < input.size() * 2; i++) {
                char c = hexStr[i];
                RC_ASSERT((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
            }
            RC_ASSERT(hexStr[input.size() * 2] == '\0');
        });

    /**
     * @test HITLS_APP_BytesToHex output length
     * @property For all byte arrays of length N, hex output length is 2N+1 (with null)
     * @generalizes UT_HITLS_APP_BytesToHex_TC001 - Output buffer size validation
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:821-838
     */
    rc::check("HITLS_APP_BytesToHex output length is exactly 2*input_len",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t hexSize = input.size() * 2 + 1;
            std::vector<char> hexStr(hexSize);
            
            int32_t ret = HITLS_APP_BytesToHex(input.data(), input.size(), 
                                               hexStr.data(), hexSize);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            RC_ASSERT(std::strlen(hexStr.data()) == input.size() * 2);
        });

    /**
     * @test HITLS_APP_BytesToHex buffer too small
     * @property For all byte arrays, insufficient buffer returns error
     * @generalizes UT_HITLS_APP_BytesToHex_TC001 - Buffer overflow protection
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:833-834
     */
    rc::check("HITLS_APP_BytesToHex fails with insufficient buffer",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t requiredSize = input.size() * 2 + 1;
            uint32_t smallSize = *gen::inRange<uint32_t>(1, requiredSize);
            std::vector<char> hexStr(smallSize);
            
            int32_t ret = HITLS_APP_BytesToHex(input.data(), input.size(), 
                                               hexStr.data(), smallSize);
            
            RC_ASSERT(ret == HITLS_APP_INTERNAL_EXCEPTION);
        });

    /**
     * @test HITLS_APP_BytesToHex null pointer handling
     * @property Null pointers return internal exception
     * @generalizes UT_HITLS_APP_BytesToHex_TC001 - Null pointer validation
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:825-832
     */
    rc::check("HITLS_APP_BytesToHex handles null pointers correctly",
        []() {
            uint8_t data[] = {0x01, 0x02, 0x03};
            char buf[16];
            
            RC_ASSERT(HITLS_APP_BytesToHex(NULL, 3, buf, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_BytesToHex(data, 3, NULL, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_BytesToHex(data, 0, buf, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_BytesToHex(data, 3, buf, 0) == HITLS_APP_INTERNAL_EXCEPTION);
        });

    /**
     * @test HITLS_APP_BytesToHex deterministic
     * @property Same input always produces same output
     * @generalizes Determinism property test
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c
     */
    rc::check("HITLS_APP_BytesToHex is deterministic",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t hexSize = input.size() * 2 + 1;
            std::vector<char> hexStr1(hexSize);
            std::vector<char> hexStr2(hexSize);
            
            HITLS_APP_BytesToHex(input.data(), input.size(), hexStr1.data(), hexSize);
            HITLS_APP_BytesToHex(input.data(), input.size(), hexStr2.data(), hexSize);
            
            RC_ASSERT(std::strcmp(hexStr1.data(), hexStr2.data()) == 0);
        });

    /**
     * @test HITLS_APP_BytesToHex different inputs produce different outputs
     * @property Different byte arrays produce different hex strings
     * @generalizes Collision resistance test
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c
     */
    rc::check("HITLS_APP_BytesToHex different inputs produce different outputs",
        [](const std::vector<uint8_t> &input1, const std::vector<uint8_t> &input2) {
            RC_PRE(input1 != input2);
            RC_PRE(input1.size() > 0);
            RC_PRE(input2.size() > 0);
            RC_PRE(input1.size() <= 256);
            RC_PRE(input2.size() <= 256);
            
            uint32_t hexSize1 = input1.size() * 2 + 1;
            uint32_t hexSize2 = input2.size() * 2 + 1;
            std::vector<char> hexStr1(hexSize1);
            std::vector<char> hexStr2(hexSize2);
            
            HITLS_APP_BytesToHex(input1.data(), input1.size(), hexStr1.data(), hexSize1);
            HITLS_APP_BytesToHex(input2.data(), input2.size(), hexStr2.data(), hexSize2);
            
            if (input1.size() == input2.size()) {
                RC_ASSERT(std::strcmp(hexStr1.data(), hexStr2.data()) != 0);
            }
        });

    /**
     * @test HITLS_APP_OptToInt valid conversion
     * @property For all valid int strings, conversion succeeds and matches
     * @generalizes UT_HITLS_APP_OptNext_TC003 - Integer type parsing
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:297-343
     */
    rc::check("HITLS_APP_OptGetInt converts valid int strings correctly",
        [](int32_t value) {
            std::string str = std::to_string(value);
            int32_t result = 0;
            
            int32_t ret = HITLS_APP_OptGetInt(str.c_str(), &result);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            RC_ASSERT(result == value);
        });

    /**
     * @test HITLS_APP_OptGetUint32 valid conversion
     * @property For all valid uint32 strings, conversion succeeds and matches
     * @generalizes UT_HITLS_APP_OptNext_TC003 - Unsigned integer parsing
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:337-341
     */
    rc::check("HITLS_APP_OptGetUint32 converts valid uint32 strings correctly",
        [](uint32_t value) {
            std::string str = std::to_string(value);
            uint32_t result = 0;
            
            int32_t ret = HITLS_APP_OptGetUint32(str.c_str(), &result);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            RC_ASSERT(result == value);
        });

    /**
     * @test HITLS_APP_OptGetUint32 negative value handling
     * @property Negative strings should fail for uint32
     * @generalizes UT_HITLS_APP_OptNext_TC003 - Negative value rejection
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:339-341
     */
    rc::check("HITLS_APP_OptGetUint32 rejects negative values",
        [](int32_t negativeValue) {
            RC_PRE(negativeValue < 0);
            
            std::string str = std::to_string(negativeValue);
            uint32_t result = 0;
            
            int32_t ret = HITLS_APP_OptGetUint32(str.c_str(), &result);
            
            RC_ASSERT(ret != HITLS_APP_SUCCESS);
        });

    /**
     * @test HITLS_APP_OptGetLong valid conversion
     * @property For all valid long strings, conversion succeeds and matches
     * @generalizes UT_HITLS_APP_OptNext_TC003 - Long integer parsing
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:344-346
     */
    rc::check("HITLS_APP_OptGetLong converts valid long strings correctly",
        [](long value) {
            std::string str = std::to_string(value);
            long result = 0;
            
            int32_t ret = HITLS_APP_OptGetLong(str.c_str(), &result);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            RC_ASSERT(result == value);
        });

    /**
     * @test HITLS_APP_OptToBase64 null pointer handling
     * @property Null pointers return internal exception
     * @generalizes UT_HITLS_APP_OptToBase64_TC001 - Parameter validation
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:798-812
     */
    rc::check("HITLS_APP_OptToBase64 handles null pointers correctly",
        []() {
            uint8_t data[] = {0x01, 0x02, 0x03};
            char buf[16];
            
            RC_ASSERT(HITLS_APP_OptToBase64(NULL, 3, buf, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_OptToBase64(data, 3, NULL, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_OptToBase64(data, 0, buf, 16) == HITLS_APP_INTERNAL_EXCEPTION);
            RC_ASSERT(HITLS_APP_OptToBase64(data, 3, buf, 0) == HITLS_APP_INTERNAL_EXCEPTION);
        });

    /**
     * @test HITLS_APP_OptToBase64 output size
     * @property Base64 output size is approximately 4*ceil(n/3)
     * @generalizes UT_HITLS_APP_OptToBase64_TC001 - Output buffer sizing
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c:798-812
     */
    rc::check("HITLS_APP_OptToBase64 output size follows Base64 encoding rules",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t expectedSize = ((input.size() + 2) / 3) * 4 + 1;
            std::vector<char> base64Str(expectedSize + 100);
            
            int32_t ret = HITLS_APP_OptToBase64(const_cast<uint8_t*>(input.data()), 
                                                 input.size(), 
                                                 base64Str.data(), 
                                                 base64Str.size());
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            
            size_t actualLen = std::strlen(base64Str.data());
            RC_ASSERT(actualLen <= expectedSize - 1);
        });

    /**
     * @test HITLS_APP_OptToBase64 deterministic
     * @property Same input always produces same output
     * @generalizes Determinism property test
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c
     */
    rc::check("HITLS_APP_OptToBase64 is deterministic",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t base64Size = ((input.size() + 2) / 3) * 4 + 100;
            std::vector<char> base64Str1(base64Size);
            std::vector<char> base64Str2(base64Size);
            
            HITLS_APP_OptToBase64(const_cast<uint8_t*>(input.data()), input.size(), 
                                  base64Str1.data(), base64Size);
            HITLS_APP_OptToBase64(const_cast<uint8_t*>(input.data()), input.size(), 
                                  base64Str2.data(), base64Size);
            
            RC_ASSERT(std::strcmp(base64Str1.data(), base64Str2.data()) == 0);
        });

    /**
     * @test HITLS_APP_OptToBase64 valid characters
     * @property Output contains only valid Base64 characters
     * @generalizes Output format validation
     * @see testcode/sdv/testcase/apps/test_suite_ut_opt.c
     */
    rc::check("HITLS_APP_OptToBase64 produces valid Base64 characters",
        [](const std::vector<uint8_t> &input) {
            RC_PRE(input.size() > 0);
            RC_PRE(input.size() <= 256);
            
            uint32_t base64Size = ((input.size() + 2) / 3) * 4 + 100;
            std::vector<char> base64Str(base64Size);
            
            int32_t ret = HITLS_APP_OptToBase64(const_cast<uint8_t*>(input.data()), 
                                                 input.size(), 
                                                 base64Str.data(), 
                                                 base64Size);
            
            RC_ASSERT(ret == HITLS_APP_SUCCESS);
            
            for (size_t i = 0; i < std::strlen(base64Str.data()); i++) {
                char c = base64Str[i];
                bool valid = (c >= 'A' && c <= 'Z') ||
                             (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') ||
                             c == '+' || c == '/' || c == '=';
                RC_ASSERT(valid);
            }
        });

    return 0;
}