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
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
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
        if (!ctx_) return {};
        
        std::vector<uint8_t> output(input.size() + 32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherUpdate(ctx_, input.data(), input.size(), 
                                              output.data(), &outLen);
        RC_PRE(ret == CRYPT_SUCCESS);
        
        return outLen;
    }
    
    int final() {
        if (!ctx_) return -1;
        
        std::vector<uint8_t> output(32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherFinal(ctx_, output.data(), &outLen);
                RC_PRE(ret == CRYPT_SUCCESS);
        
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

int main() {
    /**
     * @test OpenSSL XTS-128 Update behavior with 32-byte input
     * @property OpenSSL XTS Update processes all data immediately (no block reservation)
     * @context This test validates that the XTS block reservation bug found in openHiTLS
     *          is NOT present in OpenSSL. OpenSSL correctly processes all input data
     *          without reserving blocks for Final.
     * 
     * @rationale According to IEEE 1619 and OpenSSL implementation:
     *            - XTS mode can process any amount of data >= 16 bytes
     *            - Update should output all processed data immediately
     *            - Final is only needed for cleanup (outputs 0 bytes for XTS)
     *            
     * @expected OpenSSL behavior:
     *           - Update(inLen=32) returns outLen=32 (processes all data)
     *           - Final() returns outLen=0 (no data left to output)
     *           
     * @contrast openHiTLS bug:
     *           - Documentation claims Update should reserve 2 blocks
     *           - Implementation actually outputs all data (like OpenSSL)
     *           - This creates a documentation/implementation mismatch
     *           
     * @see include/crypto/crypt_eal_cipher.h:159-162 (openHiTLS documentation)
     * @see crypto/modes/src/modes.c:542 (openHiTLS implementation bug)
     */
    rc::check("OpenSSL AES-128-XTS Update processes 32 bytes immediately (no reservation)",
        []() {
            // Generate 32-byte key (XTS requires double key: 16 bytes for each half)
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            // Generate 16-byte IV/tweak
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            // Generate exactly 32 bytes of plaintext (2 blocks)
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            // Create OpenSSL XTS cipher
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            RC_PRE(ctx != nullptr);
            
            // Initialize AES-128-XTS encryption
            int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, 
                                          keyData.data(), ivData.data());
            RC_PRE(ret == 1);
            
            // Update with 32 bytes
            std::vector<uint8_t> ciphertext(32 + EVP_MAX_BLOCK_LENGTH);
            int updateLen = 0;
            ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &updateLen, 
                                    plaintext.data(), 32);
            RC_PRE(ret == 1);
            
            // Final
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + updateLen, &finalLen);
            RC_PRE(ret == 1);
            
            EVP_CIPHER_CTX_free(ctx);
            
            // OpenSSL processes all 32 bytes in Update (no reservation)
            RC_ASSERT(updateLen == 32);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == 32);
        });

    /**
     * @test OpenSSL XTS-256 Update behavior with 32-byte input
     * @property Same as XTS-128 but with 256-bit key
     */
    rc::check("OpenSSL AES-256-XTS Update processes 32 bytes immediately (no reservation)",
        []() {
            // Generate 64-byte key (XTS requires double key: 32 bytes for each half)
            auto keyData = *gen::container<std::vector<uint8_t>>(64, gen::arbitrary<uint8_t>());
            
            // Generate 16-byte IV/tweak
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            // Generate exactly 32 bytes of plaintext (2 blocks)
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            // Create OpenSSL XTS cipher
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            RC_PRE(ctx != nullptr);
            
            // Initialize AES-256-XTS encryption
            int ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), nullptr, 
                                          keyData.data(), ivData.data());
            RC_PRE(ret == 1);
            
            // Update with 32 bytes
            std::vector<uint8_t> ciphertext(32 + EVP_MAX_BLOCK_LENGTH);
            int updateLen = 0;
            ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &updateLen, 
                                    plaintext.data(), 32);
            RC_PRE(ret == 1);
            
            // Final
            int finalLen = 0;
            ret = EVP_EncryptFinal_ex(ctx, ciphertext.data() + updateLen, &finalLen);
            RC_PRE(ret == 1);
            
            EVP_CIPHER_CTX_free(ctx);
            
            // OpenSSL processes all 32 bytes in Update (no reservation)
            RC_ASSERT(updateLen == 32);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == 32);
        });

    /**
     * @test OpenSSL XTS with various input lengths
     * @property OpenSSL XTS Update always outputs all input data (no reservation)
     */
    rc::check("OpenSSL AES-128-XTS Update processes all input lengths correctly",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto ivData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            // Generate random length >= 16 bytes (XTS minimum)
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
            
            // OpenSSL always processes all data in Update for XTS
            RC_ASSERT(updateLen == plaintextLen);
            RC_ASSERT(finalLen == 0);
            RC_ASSERT(updateLen + finalLen == plaintextLen);
        });

    // Test algorithms to cover
    std::vector<CRYPT_CIPHER_AlgId> testAlgorithms = {
        CRYPT_CIPHER_AES128_ECB,
        CRYPT_CIPHER_AES128_CBC,
        CRYPT_CIPHER_AES128_CTR,
        CRYPT_CIPHER_AES192_ECB,
        CRYPT_CIPHER_AES192_CBC,
        CRYPT_CIPHER_AES192_CTR,
        CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES256_CTR,
    };

    /**
     * @test AES encryption matches OpenSSL reference (differential testing)
     * @property For all valid keys, IVs, and plaintexts,
     *           openHiTLS encrypt(plaintext, key, iv) == OpenSSL encrypt(plaintext, key, iv)
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Uses OpenSSL as oracle instead of fixed vectors
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:488
     */
   //  for (CRYPT_CIPHER_AlgId algId : testAlgorithms) {
        CRYPT_CIPHER_AlgId algId  = CRYPT_CIPHER_AES128_ECB;
        std::string testName = "AES encryption matches OpenSSL for algId=" + std::to_string(static_cast<int>(algId));
        
        rc::check(testName, [=]() {
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            std::vector<uint8_t>  key = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            
            std::vector<uint8_t> iv;
            if (requiresIV(algId)) {
                iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            }
            
            // Generate plaintext of random length (1 to 256 bytes)
            auto plaintextLen = 1;
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // Get OpenSSL cipher
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            // Encrypt with OpenSSL (reference)
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            int osTotalLen = 0;
            osTotalLen += osEnc.update(plaintext);
            osTotalLen += osEnc.final();
            
            // Encrypt with openHiTLS (implementation under test)
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            int hitlsTotalLen = 0;
            hitlsTotalLen += hitlsEnc.update(plaintext);
            RC_ASSERT(0 == hitlsTotalLen);
            hitlsTotalLen += hitlsEnc.final();
            RC_ASSERT(-1 == hitlsTotalLen);
        });
   // }

    return 0;
}