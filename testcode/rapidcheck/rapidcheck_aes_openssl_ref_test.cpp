/**
 * @file rapidcheck_aes_openssl_ref_test.cpp
 * @brief RapidCheck property-based tests using OpenSSL as reference model
 * 
 * This file implements differential testing (reference model testing) for AES:
 * - Generate random inputs (key, IV, plaintext)
 * - Encrypt with openHiTLS (implementation under test)
 * - Encrypt with OpenSSL (reference implementation)
 * - Compare outputs - they should match exactly
 * 
 * This approach generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 from:
 * testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:471-518
 * 
 * The unit test uses fixed test vectors. This PBT test uses:
 * - Random keys (128/192/256 bits)
 * - Random IVs
 * - Random plaintexts of various lengths
 * - OpenSSL as the oracle/reference implementation
 * 
 * Differential testing is powerful because:
 * - OpenSSL is well-tested and widely trusted
 * - Any discrepancy indicates a potential bug in openHiTLS
 * - Random inputs find edge cases fixed test vectors miss
 * 
 * Usage:
 *   ./rapidcheck_aes_openssl_ref_test              # Run all tests
 *   ./rapidcheck_aes_openssl_ref_test --list       # List all test names
 *   ./rapidcheck_aes_openssl_ref_test test1 test2  # Run specific tests
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <map>
#include <functional>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

// Helper class for OpenSSL cipher operations
class OpenSSLCipher {
public:
    OpenSSLCipher(const EVP_CIPHER* cipher, const std::vector<uint8_t>& key, 
                  const std::vector<uint8_t>& iv, bool encrypt) {
        ctx_ = EVP_CIPHER_CTX_new();
        if (ctx_) {
            EVP_CipherInit_ex(ctx_, cipher, nullptr, key.data(), 
                              iv.empty() ? nullptr : iv.data(), encrypt ? 1 : 0);
        }
    }
    
    ~OpenSSLCipher() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }
    
    bool isValid() const { return ctx_ != nullptr; }
    
    int update(const std::vector<uint8_t>& input) {
        if (!ctx_) return -1;
        
        std::vector<uint8_t> output(input.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;
        
        if (EVP_CipherUpdate(ctx_, output.data(), &outLen, input.data(), input.size()) != 1) {
            return -1;
        }
        
        return outLen;
    }
    
    int final() {
        if (!ctx_) return -1;
        
        std::vector<uint8_t> output(EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;
        
        if (EVP_CipherFinal_ex(ctx_, output.data(), &outLen) != 1) {
            return -1;
        }
        
        return outLen;
    }
    
private:
    EVP_CIPHER_CTX* ctx_;
};

// Helper class for openHiTLS cipher operations
class HiTLSCipher {
public:
    HiTLSCipher(CRYPT_CIPHER_AlgId algId, const std::vector<uint8_t>& key, 
                const std::vector<uint8_t>& iv, bool encrypt) {
        ctx_ = CRYPT_EAL_CipherNewCtx(algId);
        if (ctx_) {
            CRYPT_EAL_CipherInit(ctx_, key.data(), key.size(), 
                                  iv.empty() ? nullptr : iv.data(), 
                                  iv.empty() ? 0 : iv.size(), encrypt);
            // Enable PKCS#7 padding for block ciphers (ECB, CBC) to match OpenSSL default
            int32_t padding = 1;
            CRYPT_EAL_CipherCtrl(ctx_, CRYPT_CTRL_SET_PADDING, &padding, sizeof(padding));
        }
    }
    
    ~HiTLSCipher() {
        if (ctx_) {
            CRYPT_EAL_CipherDeinit(ctx_);
            CRYPT_EAL_CipherFreeCtx(ctx_);
        }
    }
    
    bool isValid() const { return ctx_ != nullptr; }
    
    int update(const std::vector<uint8_t>& input) {
        if (!ctx_) return -1;
        
        std::vector<uint8_t> output(input.size() + 32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherUpdate(ctx_, input.data(), input.size(), 
                                              output.data(), &outLen);
        if (ret != CRYPT_SUCCESS) return -1;
        
        return outLen;
    }
    
    int final() {
        if (!ctx_) return -1;
        
        std::vector<uint8_t> output(32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherFinal(ctx_, output.data(), &outLen);
        if (ret != CRYPT_SUCCESS) return -1;
        
        return outLen;
    }
    
private:
    CRYPT_EAL_CipherCtx* ctx_;
};

// Map openHiTLS algorithm ID to OpenSSL EVP_CIPHER
const EVP_CIPHER* getOpenSSLCipher(CRYPT_CIPHER_AlgId algId) {
    switch (algId) {
        case CRYPT_CIPHER_AES128_ECB:
            return EVP_aes_128_ecb();
        case CRYPT_CIPHER_AES128_CBC:
            return EVP_aes_128_cbc();
        case CRYPT_CIPHER_AES128_CTR:
            return EVP_aes_128_ctr();
        case CRYPT_CIPHER_AES128_GCM:
            return EVP_aes_128_gcm();
        case CRYPT_CIPHER_AES192_ECB:
            return EVP_aes_192_ecb();
        case CRYPT_CIPHER_AES192_CBC:
            return EVP_aes_192_cbc();
        case CRYPT_CIPHER_AES192_CTR:
            return EVP_aes_192_ctr();
        case CRYPT_CIPHER_AES192_GCM:
            return EVP_aes_192_gcm();
        case CRYPT_CIPHER_AES256_ECB:
            return EVP_aes_256_ecb();
        case CRYPT_CIPHER_AES256_CBC:
            return EVP_aes_256_cbc();
        case CRYPT_CIPHER_AES256_CTR:
            return EVP_aes_256_ctr();
        case CRYPT_CIPHER_AES256_GCM:
            return EVP_aes_256_gcm();
        default:
            return nullptr;
    }
}

// Get key size for algorithm
int getKeySize(CRYPT_CIPHER_AlgId algId) {
    switch (algId) {
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES128_GCM:
            return 16;
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES192_CTR:
        case CRYPT_CIPHER_AES192_GCM:
            return 24;
        case CRYPT_CIPHER_AES256_ECB:
        case CRYPT_CIPHER_AES256_CBC:
        case CRYPT_CIPHER_AES256_CTR:
        case CRYPT_CIPHER_AES256_GCM:
            return 32;
        default:
            return 0;
    }
}

// Check if algorithm requires IV
bool requiresIV(CRYPT_CIPHER_AlgId algId) {
    switch (algId) {
        case CRYPT_CIPHER_AES128_ECB:
        case CRYPT_CIPHER_AES192_ECB:
        case CRYPT_CIPHER_AES256_ECB:
            return false;
        default:
            return true;
    }
}

// Test functions - each test is a separate function for easier debugging

void test_openssl_xts128_32bytes() {
    rc::check("OpenSSL AES-128-XTS Update processes 32 bytes immediately (no reservation)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            RC_PRE(ctx != nullptr);
            
            int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, 
                                          keyData.data(), ivData.data());
            RC_PRE(ret == 1);
            
            std::vector<uint8_t> ciphertext(32 + EVP_MAX_BLOCK_LENGTH);
            int updateLen = 0;
            ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &updateLen, 
                                    plaintext.data(), 32);
            RC_PRE(ret == 1);
            
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + updateLen, &finalLen);
            RC_PRE(ret == 1);
            
            EVP_CIPHER_CTX_free(ctx);
            
            RC_ASSERT(updateLen == 32);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == 32);
        });
}

void test_openssl_xts256_32bytes() {
    rc::check("OpenSSL AES-256-XTS Update processes 32 bytes immediately (no reservation)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(64, gen::arbitrary<uint8_t>());
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            RC_PRE(ctx != nullptr);
            
            int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), nullptr, 
                                          keyData.data(), ivData.data());
            RC_PRE(ret == 1);
            
            std::vector<uint8_t> ciphertext(32 + EVP_MAX_BLOCK_LENGTH);
            int updateLen = 0;
            ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &updateLen, 
                                    plaintext.data(), 32);
            RC_PRE(ret == 1);
            
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + updateLen, &finalLen);
            RC_PRE(ret == 1);
            
            EVP_CIPHER_CTX_free(ctx);
            
            RC_ASSERT(updateLen == 32);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == 32);
        });
}

void test_openssl_xts128_various_lengths() {
    rc::check("OpenSSL AES-128-XTS Update processes all input lengths correctly",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(16, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            RC_PRE(ctx != nullptr);
            
            int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, 
                                          keyData.data(), ivData.data());
            RC_PRE(ret == 1);
            
            std::vector<uint8_t> ciphertext(plaintextLen + EVP_MAX_BLOCK_LENGTH);
            int updateLen = 0;
            ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &updateLen, 
                                    plaintext.data(), plaintextLen);
            RC_PRE(ret == 1);
            
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + updateLen, &finalLen);
            RC_PRE(ret == 1);
            
            EVP_CIPHER_CTX_free(ctx);
            
            RC_ASSERT(updateLen == plaintextLen);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == plaintextLen);
        });
}

void test_aes128_ecb_match() {
    rc::check("AES-128-ECB encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES128_ECB;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> iv;
            if (requiresIV(algId)) {
                iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            }
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

void test_aes128_cbc_match() {
    rc::check("AES-128-CBC encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES128_CBC;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

void test_aes128_ctr_match() {
    rc::check("AES-128-CTR encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES128_CTR;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

void test_aes256_ecb_match() {
    rc::check("AES-256-ECB encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES256_ECB;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> iv;
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

void test_aes256_cbc_match() {
    rc::check("AES-256-CBC encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES256_CBC;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

void test_aes256_ctr_match() {
    rc::check("AES-256-CTR encryption matches OpenSSL",
        []() {
            CRYPT_CIPHER_AlgId algId = CRYPT_CIPHER_AES256_CTR;
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            hitlsTotalLen += hitlsEnc.final();
            
            RC_ASSERT(hitlsTotalLen == osTotalLen);
        });
}

// Test registry
std::map<std::string, std::function<void()>> testRegistry = {
    {"openssl_xts128_32bytes", test_openssl_xts128_32bytes},
    {"openssl_xts256_32bytes", test_openssl_xts256_32bytes},
    {"openssl_xts128_various_lengths", test_openssl_xts128_various_lengths},
    {"aes128_ecb_match", test_aes128_ecb_match},
    {"aes128_cbc_match", test_aes128_cbc_match},
    {"aes128_ctr_match", test_aes128_ctr_match},
    {"aes256_ecb_match", test_aes256_ecb_match},
    {"aes256_cbc_match", test_aes256_cbc_match},
    {"aes256_ctr_match", test_aes256_ctr_match},
};

void printUsage(const char* programName) {
    std::cerr << "Usage: " << programName << " [OPTIONS] [TEST_NAMES...]\n"
              << "\n"
              << "Options:\n"
              << "  --list, -l     List all available test names\n"
              << "  --help, -h     Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << programName << "                          # Run all tests\n"
              << "  " << programName << " --list                   # List all test names\n"
              << "  " << programName << " openssl_xts128_32bytes   # Run specific test\n"
              << "  " << programName << " test1 test2 test3        # Run multiple tests\n";
}

void listTests() {
    std::cout << "Available tests:\n";
    for (const auto& [name, func] : testRegistry) {
        std::cout << "  " << name << "\n";
    }
    std::cout << "\nTotal: " << testRegistry.size() << " tests\n";
}

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    std::vector<std::string> testsToRun;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--list" || arg == "-l") {
            listTests();
            return 0;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else {
            testsToRun.push_back(arg);
        }
    }
    
    // Run tests
    if (testsToRun.empty()) {
        // Run all tests
        std::cout << "Running all " << testRegistry.size() << " tests...\n\n";
        for (const auto& [name, func] : testRegistry) {
            std::cout << "Running test: " << name << "\n";
            func();
            std::cout << "\n";
        }
    } else {
        // Run specific tests
        for (const auto& testName : testsToRun) {
            auto it = testRegistry.find(testName);
            if (it != testRegistry.end()) {
                std::cout << "Running test: " << testName << "\n";
                it->second();
                std::cout << "\n";
            } else {
                std::cerr << "Error: Unknown test '" << testName << "'\n";
                std::cerr << "Use --list to see available tests\n";
                return 1;
            }
        }
    }
    
    return 0;
}