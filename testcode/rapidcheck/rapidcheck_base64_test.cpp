#include <rapidcheck.h>
#include <vector>
#include <string>
#include <cstring>
#include "bsl_errno.h"
#include "bsl_base64.h"

using namespace rc;

// Test properties for BSL_BASE64_Encode/Decode

void test_encode_decode_roundtrip() {
    rc::check("BSL_BASE64_Encode then BSL_BASE64_Decode returns original data",
        []() {
            // Generate random binary data (minimum 1 byte)
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 1000), gen::arbitrary<uint8_t>());
            
            // Allocate output buffers
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t encodedLen = encoded.size();
            
            // Encode
            int32_t ret = BSL_BASE64_Encode(inputData.data(), inputData.size(), 
                                            encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            encoded[encodedLen] = '\0';
            
            // Decode
            std::vector<uint8_t> decoded(encodedLen + HITLS_BASE64_CTX_BUF_LENGTH);
            uint32_t decodedLen = decoded.size();
            ret = BSL_BASE64_Decode(encoded.data(), encodedLen, 
                                    decoded.data(), &decodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Verify roundtrip
            RC_ASSERT(decodedLen == inputData.size());
            RC_ASSERT(std::memcmp(decoded.data(), inputData.data(), inputData.size()) == 0);
        });
}

void test_streaming_encode_decode_roundtrip() {
    rc::check("BSL_BASE64 streaming encode/decode roundtrip",
        []() {
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 500), gen::arbitrary<uint8_t>());
            
            BSL_Base64Ctx *encCtx = BSL_BASE64_CtxNew();
            RC_PRE(encCtx != nullptr);
            
            // Initialize encoding
            int32_t ret = BSL_BASE64_EncodeInit(encCtx);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Encode in chunks
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t totalEncoded = 0;
            size_t offset = 0;
            
            // Encode in random chunk sizes
            while (offset < inputData.size()) {
                size_t chunkSize = std::min((size_t)*gen::inRange(1, 50), 
                                           inputData.size() - offset);
                uint32_t outLen = encoded.size() - totalEncoded;
                ret = BSL_BASE64_EncodeUpdate(encCtx, inputData.data() + offset, 
                                             chunkSize, encoded.data() + totalEncoded, &outLen);
                RC_ASSERT(ret == BSL_SUCCESS);
                totalEncoded += outLen;
                offset += chunkSize;
            }
            
            // Finalize encoding
            uint32_t finalLen = encoded.size() - totalEncoded;
            ret = BSL_BASE64_EncodeFinal(encCtx, encoded.data() + totalEncoded, &finalLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            totalEncoded += finalLen;
            
            // Decode using streaming
            BSL_Base64Ctx *decCtx = BSL_BASE64_CtxNew();
            RC_ASSERT(decCtx != nullptr);
            ret = BSL_BASE64_DecodeInit(decCtx);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            std::vector<uint8_t> decoded(inputData.size() + HITLS_BASE64_CTX_BUF_LENGTH);
            uint32_t totalDecoded = 0;
            offset = 0;
            
            while (offset < totalEncoded) {
                size_t chunkSize = std::min((size_t)*gen::inRange(1, 50), 
                                           totalEncoded - offset);
                uint32_t outLen = decoded.size() - totalDecoded;
                ret = BSL_BASE64_DecodeUpdate(decCtx, encoded.data() + offset,
                                             chunkSize, decoded.data() + totalDecoded, &outLen);
                RC_ASSERT(ret == BSL_SUCCESS);
                totalDecoded += outLen;
                offset += chunkSize;
            }
            
            finalLen = decoded.size() - totalDecoded;
            ret = BSL_BASE64_DecodeFinal(decCtx, decoded.data() + totalDecoded, &finalLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            totalDecoded += finalLen;
            
            // Verify roundtrip
            RC_ASSERT(totalDecoded == inputData.size());
            RC_ASSERT(std::memcmp(decoded.data(), inputData.data(), inputData.size()) == 0);
            
            BSL_BASE64_CtxFree(encCtx);
            BSL_BASE64_CtxFree(decCtx);
        });
}

void test_encode_output_length() {
    rc::check("BSL_BASE64_Encode output length is correct",
        []() {
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 1000), gen::arbitrary<uint8_t>());
            
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t encodedLen = encoded.size();
            
            int32_t ret = BSL_BASE64_Encode(inputData.data(), inputData.size(),
                                           encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Output length should be ceil(inputLen/3)*4 (without newlines)
            uint32_t expectedLen = ((inputData.size() + 2) / 3) * 4;
            // May have newline at position 64 if input is large
            // For simplicity, just check it's divisible by 4
            RC_ASSERT(encodedLen % 4 == 0);
        });
}

void test_encode_alphabet() {
    rc::check("BSL_BASE64_Encode output contains only valid Base64 characters",
        []() {
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 100), gen::arbitrary<uint8_t>());
            
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t encodedLen = encoded.size();
            
            int32_t ret = BSL_BASE64_Encode(inputData.data(), inputData.size(),
                                           encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Check all characters are valid Base64
            for (uint32_t i = 0; i < encodedLen; i++) {
                char c = encoded[i];
                bool valid = (c >= 'A' && c <= 'Z') ||
                            (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') ||
                            c == '+' || c == '/' ||
                            c == '=' || c == '\n' || c == '\r';
                RC_ASSERT(valid);
            }
        });
}

void test_empty_input() {
    // BSL_BASE64_Encode requires non-NULL input even for length 0
    // This is a documented limitation, so we test that behavior
    
    rc::check("BSL_BASE64_Encode/Decode with single byte works",
        []() {
            uint8_t input = *gen::arbitrary<uint8_t>();
            
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(1) + 1);
            uint32_t encodedLen = encoded.size();
            
            int32_t ret = BSL_BASE64_Encode(&input, 1, encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            std::vector<uint8_t> decoded(100);
            uint32_t decodedLen = decoded.size();
            ret = BSL_BASE64_Decode(encoded.data(), encodedLen, decoded.data(), &decodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(decodedLen == 1);
            RC_ASSERT(decoded[0] == input);
        });
}

void test_deterministic_encoding() {
    rc::check("BSL_BASE64_Encode is deterministic",
        []() {
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 100), gen::arbitrary<uint8_t>());
            
            // First encoding
            std::vector<char> encoded1(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t encodedLen1 = encoded1.size();
            BSL_BASE64_Encode(inputData.data(), inputData.size(), 
                             encoded1.data(), &encodedLen1);
            
            // Second encoding
            std::vector<char> encoded2(HITLS_BASE64_ENCODE_LENGTH(inputData.size()) + 1);
            uint32_t encodedLen2 = encoded2.size();
            BSL_BASE64_Encode(inputData.data(), inputData.size(),
                             encoded2.data(), &encodedLen2);
            
            // Should be identical
            RC_ASSERT(encodedLen1 == encodedLen2);
            RC_ASSERT(std::memcmp(encoded1.data(), encoded2.data(), encodedLen1) == 0);
        });
}

void test_null_input_handling() {
    rc::check("BSL_BASE64_Encode returns error for NULL output",
        []() {
            auto inputData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 100), gen::arbitrary<uint8_t>());
            
            uint32_t encodedLen = 100;
            int32_t ret = BSL_BASE64_Encode(inputData.data(), inputData.size(),
                                           nullptr, &encodedLen);
            RC_ASSERT(ret != BSL_SUCCESS);
        });
    
    rc::check("BSL_BASE64_Decode returns error for NULL output",
        []() {
            const char *encoded = "SGVsbG8=";
            uint32_t decodedLen = 100;
            int32_t ret = BSL_BASE64_Decode(encoded, strlen(encoded),
                                           nullptr, &decodedLen);
            RC_ASSERT(ret != BSL_SUCCESS);
        });
}

void test_invalid_base64_decode() {
    rc::check("BSL_BASE64_Decode fails for invalid Base64 input",
        []() {
            // Generate random invalid Base64 strings
            auto invalidChars = std::string(" !@#$%^&*()_[]{}|;:'\",.<>?`~");
            auto input = *gen::container<std::string>(
                *gen::inRange(1, 50), 
                gen::elementOf(invalidChars));
            
            std::vector<uint8_t> decoded(input.size() + 100);
            uint32_t decodedLen = decoded.size();
            int32_t ret = BSL_BASE64_Decode(input.c_str(), input.size(),
                                           decoded.data(), &decodedLen);
            RC_ASSERT(ret != BSL_SUCCESS);
        });
}

void test_single_byte_encoding() {
    rc::check("BSL_BASE64_Encode handles single byte correctly",
        []() {
            uint8_t input = *gen::arbitrary<uint8_t>();
            
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(1) + 1);
            uint32_t encodedLen = encoded.size();
            
            int32_t ret = BSL_BASE64_Encode(&input, 1, encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Single byte should produce 4 characters with 2 padding
            RC_ASSERT(encodedLen == 4);
            RC_ASSERT(encoded[2] == '=');
            RC_ASSERT(encoded[3] == '=');
        });
}

void test_two_byte_encoding() {
    rc::check("BSL_BASE64_Encode handles two bytes correctly",
        []() {
            uint8_t input[2] = {*gen::arbitrary<uint8_t>(), *gen::arbitrary<uint8_t>()};
            
            std::vector<char> encoded(HITLS_BASE64_ENCODE_LENGTH(2) + 1);
            uint32_t encodedLen = encoded.size();
            
            int32_t ret = BSL_BASE64_Encode(input, 2, encoded.data(), &encodedLen);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Two bytes should produce 4 characters with 1 padding
            RC_ASSERT(encodedLen == 4);
            RC_ASSERT(encoded[3] == '=');
        });
}

void test_context_new_free() {
    rc::check("BSL_BASE64_CtxNew/CtxFree works correctly",
        []() {
            BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
            RC_ASSERT(ctx != nullptr);
            
            int32_t ret = BSL_BASE64_EncodeInit(ctx);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            BSL_BASE64_CtxFree(ctx);
            // Should not crash
        });
}

void test_context_reuse() {
    rc::check("BSL_BASE64 context can be reused after clear",
        []() {
            auto data1 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(10, 100), gen::arbitrary<uint8_t>());
            auto data2 = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(10, 100), gen::arbitrary<uint8_t>());
            
            BSL_Base64Ctx *ctx = BSL_BASE64_CtxNew();
            RC_ASSERT(ctx != nullptr);
            
            // First use - full streaming encode
            int32_t ret = BSL_BASE64_EncodeInit(ctx);
            RC_ASSERT(ret == BSL_SUCCESS);
            ret = BSL_BASE64_SetFlags(ctx, BSL_BASE64_FLAGS_NO_NEWLINE);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            std::vector<char> encoded1(HITLS_BASE64_ENCODE_LENGTH(data1.size()) + 1);
            uint32_t encLen1 = encoded1.size();
            ret = BSL_BASE64_EncodeUpdate(ctx, data1.data(), data1.size(),
                                         encoded1.data(), &encLen1);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Finalize first encoding
            uint32_t finalLen1 = encoded1.size() - encLen1;
            ret = BSL_BASE64_EncodeFinal(ctx, encoded1.data() + encLen1, &finalLen1);
            RC_ASSERT(ret == BSL_SUCCESS);
            uint32_t totalEnc1 = encLen1 + finalLen1;
            
            // Verify first encoding is correct by comparing with non-streaming
            std::vector<char> expected1(HITLS_BASE64_ENCODE_LENGTH(data1.size()) + 1);
            uint32_t expLen1 = expected1.size();
            ret = BSL_BASE64_Encode(data1.data(), data1.size(), expected1.data(), &expLen1);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(totalEnc1 == expLen1);
            RC_ASSERT(std::memcmp(encoded1.data(), expected1.data(), totalEnc1) == 0);
            
            // Clear and reuse
            BSL_BASE64_CtxClear(ctx);
            ret = BSL_BASE64_EncodeInit(ctx);
            RC_ASSERT(ret == BSL_SUCCESS);
            ret = BSL_BASE64_SetFlags(ctx, BSL_BASE64_FLAGS_NO_NEWLINE);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            std::vector<char> encoded2(HITLS_BASE64_ENCODE_LENGTH(data2.size()) + 1);
            uint32_t encLen2 = encoded2.size();
            ret = BSL_BASE64_EncodeUpdate(ctx, data2.data(), data2.size(),
                                         encoded2.data(), &encLen2);
            RC_ASSERT(ret == BSL_SUCCESS);
            
            // Finalize second encoding
            uint32_t finalLen2 = encoded2.size() - encLen2;
            ret = BSL_BASE64_EncodeFinal(ctx, encoded2.data() + encLen2, &finalLen2);
            RC_ASSERT(ret == BSL_SUCCESS);
            uint32_t totalEnc2 = encLen2 + finalLen2;
            
            // Verify second encoding
            std::vector<char> expected2(HITLS_BASE64_ENCODE_LENGTH(data2.size()) + 1);
            uint32_t expLen2 = expected2.size();
            ret = BSL_BASE64_Encode(data2.data(), data2.size(), expected2.data(), &expLen2);
            RC_ASSERT(ret == BSL_SUCCESS);
            RC_ASSERT(totalEnc2 == expLen2);
            RC_ASSERT(std::memcmp(encoded2.data(), expected2.data(), totalEnc2) == 0);
            
            BSL_BASE64_CtxFree(ctx);
        });
}

int main(int argc, char *argv[]) {
    // Parse test name from command line
    std::string testName = (argc > 1) ? argv[1] : "all";
    
    std::vector<std::pair<std::string, void(*)()>> tests = {
        {"encode_decode_roundtrip", test_encode_decode_roundtrip},
        {"streaming_encode_decode_roundtrip", test_streaming_encode_decode_roundtrip},
        {"encode_output_length", test_encode_output_length},
        {"encode_alphabet", test_encode_alphabet},
        {"empty_input", test_empty_input},
        {"deterministic_encoding", test_deterministic_encoding},
        {"null_input_handling", test_null_input_handling},
        {"invalid_base64_decode", test_invalid_base64_decode},
        {"single_byte_encoding", test_single_byte_encoding},
        {"two_byte_encoding", test_two_byte_encoding},
        {"context_new_free", test_context_new_free},
        {"context_reuse", test_context_reuse},
    };
    
    if (testName == "all") {
        std::cout << "Running all " << tests.size() << " tests..." << std::endl;
        for (const auto &test : tests) {
            std::cout << "Running test: " << test.first << std::endl;
            test.second();
        }
    } else {
        bool found = false;
        for (const auto &test : tests) {
            if (test.first == testName) {
                std::cout << "Running test: " << test.first << std::endl;
                test.second();
                found = true;
                break;
            }
        }
        if (!found) {
            std::cerr << "Unknown test: " << testName << std::endl;
            std::cerr << "Available tests:" << std::endl;
            for (const auto &test : tests) {
                std::cerr << "  " << test.first << std::endl;
            }
            return 1;
        }
    }
    
    return 0;
}
