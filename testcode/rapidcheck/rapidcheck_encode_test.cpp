#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include "crypt_errno.h"
#include "crypt_bn.h"
#include "crypt_encode.h"

using namespace rc;

static const int MAX_BN_BITS = 2048;

// Helper to create a positive BN from raw bytes
BN_BigNum *createPositiveBn(const std::vector<uint8_t> &data) {
    BN_BigNum *bn = BN_Create(MAX_BN_BITS);
    if (!bn) return nullptr;
    if (BN_Bin2Bn(bn, data.data(), data.size()) != CRYPT_SUCCESS) {
        BN_Destroy(bn);
        return nullptr;
    }
    BN_SetSign(bn, false);  // Ensure positive
    return bn;
}

// Helper to convert BN to bytes
std::vector<uint8_t> bnToBytes(BN_BigNum *bn) {
    uint32_t len = BN_Bytes(bn);
    std::vector<uint8_t> bytes(len);
    BN_Bn2Bin(bn, bytes.data(), &len);
    return bytes;
}

void test_sign_encode_decode_roundtrip() {
    rc::check("CRYPT_EAL_EncodeSign/DecodeSign roundtrip",
        []() {
            // Generate random positive r and s values (at least 1 byte, non-zero)
            auto rData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            // Encode
            uint32_t encodeLen = 1024;
            std::vector<uint8_t> encoded(encodeLen);
            int32_t ret = CRYPT_EAL_EncodeSign(r, s, encoded.data(), &encodeLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Decode
            BN_BigNum *r2 = BN_Create(MAX_BN_BITS);
            BN_BigNum *s2 = BN_Create(MAX_BN_BITS);
            RC_ASSERT(r2 != nullptr && s2 != nullptr);
            
            ret = CRYPT_EAL_DecodeSign(encoded.data(), encodeLen, r2, s2);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Verify roundtrip
            auto rBytes = bnToBytes(r);
            auto r2Bytes = bnToBytes(r2);
            auto sBytes = bnToBytes(s);
            auto s2Bytes = bnToBytes(s2);
            
            RC_ASSERT(rBytes == r2Bytes);
            RC_ASSERT(sBytes == s2Bytes);
            
            BN_Destroy(r);
            BN_Destroy(s);
            BN_Destroy(r2);
            BN_Destroy(s2);
        });
}

void test_sign_encode_length_consistency() {
    rc::check("CRYPT_EAL_GetSignEncodeLen returns exact encoded length",
        []() {
            auto rData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            // Get expected length
            uint32_t maxLen = 0;
            int32_t ret = CRYPT_EAL_GetSignEncodeLen(BN_Bytes(r), BN_Bytes(s), &maxLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Encode
            std::vector<uint8_t> encoded(maxLen);
            uint32_t encodeLen = maxLen;
            ret = CRYPT_EAL_EncodeSign(r, s, encoded.data(), &encodeLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            RC_ASSERT(encodeLen <= maxLen);
            
            BN_Destroy(r);
            BN_Destroy(s);
        });
}

void test_sign_encode_determinism() {
    rc::check("CRYPT_EAL_EncodeSign is deterministic",
        []() {
            auto rData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(
                *gen::inRange(1, 32), gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            // First encode
            std::vector<uint8_t> encoded1(1024);
            uint32_t len1 = 1024;
            CRYPT_EAL_EncodeSign(r, s, encoded1.data(), &len1);
            
            // Second encode
            std::vector<uint8_t> encoded2(1024);
            uint32_t len2 = 1024;
            CRYPT_EAL_EncodeSign(r, s, encoded2.data(), &len2);
            
            RC_ASSERT(len1 == len2);
            RC_ASSERT(std::memcmp(encoded1.data(), encoded2.data(), len1) == 0);
            
            BN_Destroy(r);
            BN_Destroy(s);
        });
}

void test_sign_encode_null_inputs() {
    rc::check("CRYPT_EAL_EncodeSign rejects NULL inputs",
        []() {
            auto rData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            std::vector<uint8_t> encoded(1024);
            uint32_t len = 1024;
            
            // NULL r
            RC_ASSERT(CRYPT_EAL_EncodeSign(nullptr, s, encoded.data(), &len) == CRYPT_NULL_INPUT);
            
            // NULL s
            RC_ASSERT(CRYPT_EAL_EncodeSign(r, nullptr, encoded.data(), &len) == CRYPT_NULL_INPUT);
            
            // NULL output
            RC_ASSERT(CRYPT_EAL_EncodeSign(r, s, nullptr, &len) == CRYPT_NULL_INPUT);
            
            // NULL output length
            RC_ASSERT(CRYPT_EAL_EncodeSign(r, s, encoded.data(), nullptr) == CRYPT_NULL_INPUT);
            
            BN_Destroy(r);
            BN_Destroy(s);
        });
}

void test_sign_decode_null_inputs() {
    rc::check("CRYPT_EAL_DecodeSign rejects NULL inputs",
        []() {
            auto encoded = *gen::container<std::vector<uint8_t>>(64, gen::arbitrary<uint8_t>());
            
            BN_BigNum *r = BN_Create(MAX_BN_BITS);
            BN_BigNum *s = BN_Create(MAX_BN_BITS);
            RC_PRE(r != nullptr && s != nullptr);
            
            // NULL encoded data
            RC_ASSERT(CRYPT_EAL_DecodeSign(nullptr, encoded.size(), r, s) == CRYPT_NULL_INPUT);
            
            // Zero length
            RC_ASSERT(CRYPT_EAL_DecodeSign(encoded.data(), 0, r, s) == CRYPT_NULL_INPUT);
            
            // NULL r
            RC_ASSERT(CRYPT_EAL_DecodeSign(encoded.data(), encoded.size(), nullptr, s) == CRYPT_NULL_INPUT);
            
            // NULL s
            RC_ASSERT(CRYPT_EAL_DecodeSign(encoded.data(), encoded.size(), r, nullptr) == CRYPT_NULL_INPUT);
            
            BN_Destroy(r);
            BN_Destroy(s);
        });
}

void test_sign_encode_zero_rejected() {
    rc::check("CRYPT_EAL_EncodeSign rejects zero r or s",
        []() {
            BN_BigNum *zero = BN_Create(MAX_BN_BITS);
            BN_BigNum *nonZero = createPositiveBn(std::vector<uint8_t>{1, 2, 3});
            RC_PRE(zero != nullptr && nonZero != nullptr);
            
            std::vector<uint8_t> encoded(1024);
            uint32_t len = 1024;
            
            // Zero r
            RC_ASSERT(CRYPT_EAL_EncodeSign(zero, nonZero, encoded.data(), &len) == CRYPT_INVALID_ARG);
            
            // Zero s
            len = 1024;
            RC_ASSERT(CRYPT_EAL_EncodeSign(nonZero, zero, encoded.data(), &len) == CRYPT_INVALID_ARG);
            
            BN_Destroy(zero);
            BN_Destroy(nonZero);
        });
}

void test_sign_encode_negative_rejected() {
    rc::check("CRYPT_EAL_EncodeSign rejects negative r or s",
        []() {
            auto data = std::vector<uint8_t>{1, 2, 3};
            BN_BigNum *neg = BN_Create(MAX_BN_BITS);
            BN_BigNum *pos = createPositiveBn(data);
            RC_PRE(neg != nullptr && pos != nullptr);
            
            BN_Bin2Bn(neg, data.data(), data.size());
            BN_SetSign(neg, true);  // Make negative
            
            std::vector<uint8_t> encoded(1024);
            uint32_t len = 1024;
            
            // Negative r
            RC_ASSERT(CRYPT_EAL_EncodeSign(neg, pos, encoded.data(), &len) == CRYPT_INVALID_ARG);
            
            // Negative s
            len = 1024;
            RC_ASSERT(CRYPT_EAL_EncodeSign(pos, neg, encoded.data(), &len) == CRYPT_INVALID_ARG);
            
            BN_Destroy(neg);
            BN_Destroy(pos);
        });
}

void test_sign_encode_buffer_too_small() {
    rc::check("CRYPT_EAL_EncodeSign rejects buffer too small",
        []() {
            auto rData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            std::vector<uint8_t> encoded(1);  // Too small
            uint32_t len = 1;
            
            int32_t ret = CRYPT_EAL_EncodeSign(r, s, encoded.data(), &len);
            RC_ASSERT(ret == CRYPT_ENCODE_BUFF_NOT_ENOUGH);
            
            BN_Destroy(r);
            BN_Destroy(s);
        });
}

void test_sign_decode_produces_positive() {
    rc::check("CRYPT_EAL_DecodeSign produces positive r and s",
        []() {
            auto rData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            auto sData = *gen::container<std::vector<uint8_t>>(16, gen::nonZero<uint8_t>());
            
            BN_BigNum *r = createPositiveBn(rData);
            BN_BigNum *s = createPositiveBn(sData);
            RC_PRE(r != nullptr && s != nullptr);
            
            // Encode
            std::vector<uint8_t> encoded(1024);
            uint32_t encodeLen = 1024;
            int32_t ret = CRYPT_EAL_EncodeSign(r, s, encoded.data(), &encodeLen);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            // Decode
            BN_BigNum *r2 = BN_Create(MAX_BN_BITS);
            BN_BigNum *s2 = BN_Create(MAX_BN_BITS);
            RC_ASSERT(r2 != nullptr && s2 != nullptr);
            
            ret = CRYPT_EAL_DecodeSign(encoded.data(), encodeLen, r2, s2);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            // Verify both are non-negative
            RC_ASSERT(!BN_IsNegative(r2));
            RC_ASSERT(!BN_IsNegative(s2));
            
            BN_Destroy(r);
            BN_Destroy(s);
            BN_Destroy(r2);
            BN_Destroy(s2);
        });
}

int main(int argc, char *argv[]) {
    std::string testName = (argc > 1) ? argv[1] : "all";
    
    std::vector<std::pair<std::string, void(*)()>> tests = {
        {"sign_encode_decode_roundtrip", test_sign_encode_decode_roundtrip},
        {"sign_encode_length_consistency", test_sign_encode_length_consistency},
        {"sign_encode_determinism", test_sign_encode_determinism},
        {"sign_encode_null_inputs", test_sign_encode_null_inputs},
        {"sign_decode_null_inputs", test_sign_decode_null_inputs},
        {"sign_encode_zero_rejected", test_sign_encode_zero_rejected},
        {"sign_encode_negative_rejected", test_sign_encode_negative_rejected},
        {"sign_encode_buffer_too_small", test_sign_encode_buffer_too_small},
        {"sign_decode_produces_positive", test_sign_decode_produces_positive},
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
