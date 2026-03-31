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
    
    std::vector<uint8_t> update(const std::vector<uint8_t>& input) {
        if (!ctx_) return {};
        
        std::vector<uint8_t> output(input.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;
        
        if (EVP_CipherUpdate(ctx_, output.data(), &outLen, input.data(), input.size()) != 1) {
            return {};
        }
        
        output.resize(outLen);
        return output;
    }
    
    std::vector<uint8_t> final() {
        if (!ctx_) return {};
        
        std::vector<uint8_t> output(EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;
        
        if (EVP_CipherFinal_ex(ctx_, output.data(), &outLen) != 1) {
            return {};
        }
        
        output.resize(outLen);
        return output;
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
    
    std::vector<uint8_t> update(const std::vector<uint8_t>& input) {
        if (!ctx_) return {};
        
        std::vector<uint8_t> output(input.size() + 32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherUpdate(ctx_, input.data(), input.size(), 
                                              output.data(), &outLen);
        if (ret != CRYPT_SUCCESS) {
            return {};
        }
        
        output.resize(outLen);
        return output;
    }
    
    std::vector<uint8_t> final() {
        if (!ctx_) return {};
        
        std::vector<uint8_t> output(32);
        uint32_t outLen = output.size();
        
        int32_t ret = CRYPT_EAL_CipherFinal(ctx_, output.data(), &outLen);
        if (ret != CRYPT_SUCCESS) {
            return {};
        }
        
        output.resize(outLen);
        return output;
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
    for (CRYPT_CIPHER_AlgId algId : testAlgorithms) {
        std::string testName = "AES encryption matches OpenSSL for algId=" + std::to_string(static_cast<int>(algId));
        
        rc::check(testName, [=]() {
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> iv;
            if (requiresIV(algId)) {
                iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            }
            
            // Generate plaintext of random length (1 to 256 bytes)
            auto plaintextLen = *gen::inRange(1, 257);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // Get OpenSSL cipher
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            // Encrypt with OpenSSL (reference)
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osUpdateOut = osEnc.update(plaintext);
            auto osFinalOut = osEnc.final();
            
            // Combine OpenSSL output
            std::vector<uint8_t> opensslOutput;
            opensslOutput.insert(opensslOutput.end(), osUpdateOut.begin(), osUpdateOut.end());
            opensslOutput.insert(opensslOutput.end(), osFinalOut.begin(), osFinalOut.end());
            
            // Encrypt with openHiTLS (implementation under test)
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsUpdateOut = hitlsEnc.update(plaintext);
            auto hitlsFinalOut = hitlsEnc.final();
            
            // Combine openHiTLS output
            std::vector<uint8_t> hitlsOutput;
            hitlsOutput.insert(hitlsOutput.end(), hitlsUpdateOut.begin(), hitlsUpdateOut.end());
            hitlsOutput.insert(hitlsOutput.end(), hitlsFinalOut.begin(), hitlsFinalOut.end());
            
            // Compare outputs - they should match exactly
            RC_ASSERT(opensslOutput.size() == hitlsOutput.size());
            if (opensslOutput.size() > 0) {
                RC_ASSERT(std::memcmp(opensslOutput.data(), hitlsOutput.data(), opensslOutput.size()) == 0);
            }
        });
    }

    /**
     * @test AES decryption matches OpenSSL reference (differential testing)
     * @property For all valid keys, IVs, and ciphertexts,
     *           openHiTLS decrypt(ciphertext, key, iv) == OpenSSL decrypt(ciphertext, key, iv)
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Decryption variant
     */
    for (CRYPT_CIPHER_AlgId algId : testAlgorithms) {
        std::string testName = "AES decryption matches OpenSSL for algId=" + std::to_string(static_cast<int>(algId));
        
        rc::check(testName, [=]() {
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> iv;
            if (requiresIV(algId)) {
                iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            }
            
            // Generate plaintext, encrypt it first to get valid ciphertext
            auto plaintextLen = *gen::inRange(16, 129);  // Multiple of block size for simplicity
            plaintextLen = (plaintextLen / 16) * 16;     // Ensure block-aligned
            RC_PRE(plaintextLen >= 16);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // Get OpenSSL cipher
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            // Encrypt with OpenSSL to get ciphertext
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osEncUpdate = osEnc.update(plaintext);
            auto osEncFinal = osEnc.final();
            
            std::vector<uint8_t> ciphertext;
            ciphertext.insert(ciphertext.end(), osEncUpdate.begin(), osEncUpdate.end());
            ciphertext.insert(ciphertext.end(), osEncFinal.begin(), osEncFinal.end());
            
            RC_PRE(ciphertext.size() > 0);
            
            // Decrypt with OpenSSL (reference)
            OpenSSLCipher osDec(osCipher, key, iv, false);
            RC_PRE(osDec.isValid());
            
            auto osDecUpdate = osDec.update(ciphertext);
            auto osDecFinal = osDec.final();
            
            std::vector<uint8_t> opensslDecrypted;
            opensslDecrypted.insert(opensslDecrypted.end(), osDecUpdate.begin(), osDecUpdate.end());
            opensslDecrypted.insert(opensslDecrypted.end(), osDecFinal.begin(), osDecFinal.end());
            
            // Decrypt with openHiTLS (implementation under test)
            HiTLSCipher hitlsDec(algId, key, iv, false);
            RC_PRE(hitlsDec.isValid());
            
            auto hitlsDecUpdate = hitlsDec.update(ciphertext);
            auto hitlsDecFinal = hitlsDec.final();
            
            std::vector<uint8_t> hitlsDecrypted;
            hitlsDecrypted.insert(hitlsDecrypted.end(), hitlsDecUpdate.begin(), hitlsDecUpdate.end());
            hitlsDecrypted.insert(hitlsDecrypted.end(), hitlsDecFinal.begin(), hitlsDecFinal.end());
            
            // Compare decrypted outputs
            RC_ASSERT(opensslDecrypted.size() == hitlsDecrypted.size());
            if (opensslDecrypted.size() > 0) {
                RC_ASSERT(std::memcmp(opensslDecrypted.data(), hitlsDecrypted.data(), 
                                      opensslDecrypted.size()) == 0);
            }
        });
    }

    /**
     * @test AES encrypt-decrypt roundtrip matches OpenSSL
     * @property For openHiTLS: decrypt(encrypt(p, k, iv), k, iv) == p
     *           And matches OpenSSL roundtrip result
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - Full roundtrip test
     */
    for (CRYPT_CIPHER_AlgId algId : testAlgorithms) {
        std::string testName = "AES roundtrip matches OpenSSL for algId=" + std::to_string(static_cast<int>(algId));
        
        rc::check(testName, [=]() {
            int keySize = getKeySize(algId);
            RC_PRE(keySize > 0);
            
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> iv;
            if (requiresIV(algId)) {
                iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            }
            
            // Generate plaintext
            auto plaintextLen = *gen::inRange(16, 129);
            plaintextLen = (plaintextLen / 16) * 16;
            RC_PRE(plaintextLen >= 16);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            // OpenSSL roundtrip
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osEncOut = osEnc.update(plaintext);
            auto osEncFin = osEnc.final();
            std::vector<uint8_t> osCiphertext;
            osCiphertext.insert(osCiphertext.end(), osEncOut.begin(), osEncOut.end());
            osCiphertext.insert(osCiphertext.end(), osEncFin.begin(), osEncFin.end());
            
            OpenSSLCipher osDec(osCipher, key, iv, false);
            RC_PRE(osDec.isValid());
            
            auto osDecOut = osDec.update(osCiphertext);
            auto osDecFin = osDec.final();
            std::vector<uint8_t> osRoundtrip;
            osRoundtrip.insert(osRoundtrip.end(), osDecOut.begin(), osDecOut.end());
            osRoundtrip.insert(osRoundtrip.end(), osDecFin.begin(), osDecFin.end());
            
            // openHiTLS roundtrip
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsEncOut = hitlsEnc.update(plaintext);
            auto hitlsEncFin = hitlsEnc.final();
            std::vector<uint8_t> hitlsCiphertext;
            hitlsCiphertext.insert(hitlsCiphertext.end(), hitlsEncOut.begin(), hitlsEncOut.end());
            hitlsCiphertext.insert(hitlsCiphertext.end(), hitlsEncFin.begin(), hitlsEncFin.end());
            
            HiTLSCipher hitlsDec(algId, key, iv, false);
            RC_PRE(hitlsDec.isValid());
            
            auto hitlsDecOut = hitlsDec.update(hitlsCiphertext);
            auto hitlsDecFin = hitlsDec.final();
            std::vector<uint8_t> hitlsRoundtrip;
            hitlsRoundtrip.insert(hitlsRoundtrip.end(), hitlsDecOut.begin(), hitlsDecOut.end());
            hitlsRoundtrip.insert(hitlsRoundtrip.end(), hitlsDecFin.begin(), hitlsDecFin.end());
            
            // All three should match: original plaintext, OpenSSL roundtrip, openHiTLS roundtrip
            RC_ASSERT(osRoundtrip.size() == plaintext.size());
            RC_ASSERT(hitlsRoundtrip.size() == plaintext.size());
            RC_ASSERT(std::memcmp(plaintext.data(), osRoundtrip.data(), plaintext.size()) == 0);
            RC_ASSERT(std::memcmp(plaintext.data(), hitlsRoundtrip.data(), plaintext.size()) == 0);
            RC_ASSERT(std::memcmp(osRoundtrip.data(), hitlsRoundtrip.data(), plaintext.size()) == 0);
        });
    }

    /**
     * @test AES ciphertext from openHiTLS can be decrypted by OpenSSL
     * @property Cross-implementation compatibility:
     *           OpenSSL decrypt(openHiTLS encrypt(p, k, iv), k, iv) == p
     * @generalizes Tests interoperability between implementations
     */
    rc::check("OpenSSL can decrypt openHiTLS ciphertext (cross-implementation)",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_AES128_CBC, 
                                        CRYPT_CIPHER_AES192_CBC, 
                                        CRYPT_CIPHER_AES256_CBC);
            
            int keySize = getKeySize(algId);
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(16, 129);
            plaintextLen = (plaintextLen / 16) * 16;
            RC_PRE(plaintextLen >= 16);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // Encrypt with openHiTLS
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsEncOut = hitlsEnc.update(plaintext);
            auto hitlsEncFin = hitlsEnc.final();
            std::vector<uint8_t> hitlsCiphertext;
            hitlsCiphertext.insert(hitlsCiphertext.end(), hitlsEncOut.begin(), hitlsEncOut.end());
            hitlsCiphertext.insert(hitlsCiphertext.end(), hitlsEncFin.begin(), hitlsEncFin.end());
            
            // Decrypt with OpenSSL
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osDec(osCipher, key, iv, false);
            RC_PRE(osDec.isValid());
            
            auto osDecOut = osDec.update(hitlsCiphertext);
            auto osDecFin = osDec.final();
            std::vector<uint8_t> osDecrypted;
            osDecrypted.insert(osDecrypted.end(), osDecOut.begin(), osDecOut.end());
            osDecrypted.insert(osDecrypted.end(), osDecFin.begin(), osDecFin.end());
            
            // Should recover original plaintext
            RC_ASSERT(osDecrypted.size() == plaintext.size());
            RC_ASSERT(std::memcmp(plaintext.data(), osDecrypted.data(), plaintext.size()) == 0);
        });

    /**
     * @test AES ciphertext from OpenSSL can be decrypted by openHiTLS
     * @property Cross-implementation compatibility (reverse direction):
     *           openHiTLS decrypt(OpenSSL encrypt(p, k, iv), k, iv) == p
     * @generalizes Tests interoperability in both directions
     */
    rc::check("openHiTLS can decrypt OpenSSL ciphertext (cross-implementation)",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_AES128_CBC, 
                                        CRYPT_CIPHER_AES192_CBC, 
                                        CRYPT_CIPHER_AES256_CBC);
            
            int keySize = getKeySize(algId);
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            auto plaintextLen = *gen::inRange(16, 129);
            plaintextLen = (plaintextLen / 16) * 16;
            RC_PRE(plaintextLen >= 16);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // Encrypt with OpenSSL
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osEncOut = osEnc.update(plaintext);
            auto osEncFin = osEnc.final();
            std::vector<uint8_t> osCiphertext;
            osCiphertext.insert(osCiphertext.end(), osEncOut.begin(), osEncOut.end());
            osCiphertext.insert(osCiphertext.end(), osEncFin.begin(), osEncFin.end());
            
            // Decrypt with openHiTLS
            HiTLSCipher hitlsDec(algId, key, iv, false);
            RC_PRE(hitlsDec.isValid());
            
            auto hitlsDecOut = hitlsDec.update(osCiphertext);
            auto hitlsDecFin = hitlsDec.final();
            std::vector<uint8_t> hitlsDecrypted;
            hitlsDecrypted.insert(hitlsDecrypted.end(), hitlsDecOut.begin(), hitlsDecOut.end());
            hitlsDecrypted.insert(hitlsDecrypted.end(), hitlsDecFin.begin(), hitlsDecFin.end());
            
            // Should recover original plaintext
            RC_ASSERT(hitlsDecrypted.size() == plaintext.size());
            RC_ASSERT(std::memcmp(plaintext.data(), hitlsDecrypted.data(), plaintext.size()) == 0);
        });

    /**
     * @test AES ECB mode encryption matches OpenSSL (no IV)
     * @property For ECB mode (no IV), encryption outputs match
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - ECB mode specific test
     */
    rc::check("AES ECB encryption matches OpenSSL (no IV required)",
        []() {
            auto keySize = *gen::element(16, 24, 32);
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            
            CRYPT_CIPHER_AlgId algId;
            const EVP_CIPHER* osCipher;
            if (keySize == 16) {
                algId = CRYPT_CIPHER_AES128_ECB;
                osCipher = EVP_aes_128_ecb();
            } else if (keySize == 24) {
                algId = CRYPT_CIPHER_AES192_ECB;
                osCipher = EVP_aes_192_ecb();
            } else {
                algId = CRYPT_CIPHER_AES256_ECB;
                osCipher = EVP_aes_256_ecb();
            }
            
            // ECB requires block-aligned input
            auto plaintextLen = *gen::inRange(16, 129);
            plaintextLen = (plaintextLen / 16) * 16;
            RC_PRE(plaintextLen >= 16);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // OpenSSL encrypt
            OpenSSLCipher osEnc(osCipher, key, {}, true);
            RC_PRE(osEnc.isValid());
            
            auto osOut = osEnc.update(plaintext);
            auto osFin = osEnc.final();
            std::vector<uint8_t> osCipherText;
            osCipherText.insert(osCipherText.end(), osOut.begin(), osOut.end());
            osCipherText.insert(osCipherText.end(), osFin.begin(), osFin.end());
            
            // openHiTLS encrypt
            HiTLSCipher hitlsEnc(algId, key, {}, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsOut = hitlsEnc.update(plaintext);
            auto hitlsFin = hitlsEnc.final();
            std::vector<uint8_t> hitlsCipherText;
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsOut.begin(), hitlsOut.end());
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsFin.begin(), hitlsFin.end());
            
            RC_ASSERT(osCipherText.size() == hitlsCipherText.size());
            RC_ASSERT(std::memcmp(osCipherText.data(), hitlsCipherText.data(), osCipherText.size()) == 0);
        });

    /**
     * @test AES CTR mode encryption matches OpenSSL
     * @property CTR mode (stream cipher) outputs match for all input lengths
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 - CTR mode specific test
     */
    rc::check("AES CTR encryption matches OpenSSL (stream cipher mode)",
        []() {
            auto keySize = *gen::element(16, 24, 32);
            auto key = *gen::container<std::vector<uint8_t>>(keySize, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_CIPHER_AlgId algId;
            const EVP_CIPHER* osCipher;
            if (keySize == 16) {
                algId = CRYPT_CIPHER_AES128_CTR;
                osCipher = EVP_aes_128_ctr();
            } else if (keySize == 24) {
                algId = CRYPT_CIPHER_AES192_CTR;
                osCipher = EVP_aes_192_ctr();
            } else {
                algId = CRYPT_CIPHER_AES256_CTR;
                osCipher = EVP_aes_256_ctr();
            }
            
            // CTR can handle any length (no padding)
            auto plaintextLen = *gen::inRange(1, 256);
            auto plaintext = *gen::container<std::vector<uint8_t>>(plaintextLen, gen::arbitrary<uint8_t>());
            
            // OpenSSL encrypt
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osOut = osEnc.update(plaintext);
            auto osFin = osEnc.final();
            std::vector<uint8_t> osCipherText;
            osCipherText.insert(osCipherText.end(), osOut.begin(), osOut.end());
            osCipherText.insert(osCipherText.end(), osFin.begin(), osFin.end());
            
            // openHiTLS encrypt
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsOut = hitlsEnc.update(plaintext);
            auto hitlsFin = hitlsEnc.final();
            std::vector<uint8_t> hitlsCipherText;
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsOut.begin(), hitlsOut.end());
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsFin.begin(), hitlsFin.end());
            
            RC_ASSERT(osCipherText.size() == hitlsCipherText.size());
            RC_ASSERT(std::memcmp(osCipherText.data(), hitlsCipherText.data(), osCipherText.size()) == 0);
        });

    /**
     * @test Empty plaintext handling
     * @property Both implementations handle empty input consistently
     * @generalizes Edge case testing
     */
    rc::check("AES handles empty plaintext consistently with OpenSSL",
        []() {
            auto algId = *gen::element(CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES256_CBC);
            auto key = *gen::container<std::vector<uint8_t>>(getKeySize(algId), gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            std::vector<uint8_t> emptyPlaintext;
            
            const EVP_CIPHER* osCipher = getOpenSSLCipher(algId);
            RC_PRE(osCipher != nullptr);
            
            // OpenSSL encrypt empty
            OpenSSLCipher osEnc(osCipher, key, iv, true);
            RC_PRE(osEnc.isValid());
            
            auto osOut = osEnc.update(emptyPlaintext);
            auto osFin = osEnc.final();
            std::vector<uint8_t> osCipherText;
            osCipherText.insert(osCipherText.end(), osOut.begin(), osOut.end());
            osCipherText.insert(osCipherText.end(), osFin.begin(), osFin.end());
            
            // openHiTLS encrypt empty
            HiTLSCipher hitlsEnc(algId, key, iv, true);
            RC_PRE(hitlsEnc.isValid());
            
            auto hitlsOut = hitlsEnc.update(emptyPlaintext);
            auto hitlsFin = hitlsEnc.final();
            std::vector<uint8_t> hitlsCipherText;
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsOut.begin(), hitlsOut.end());
            hitlsCipherText.insert(hitlsCipherText.end(), hitlsFin.begin(), hitlsFin.end());
            
            // Both should produce same output (likely just padding block)
            RC_ASSERT(osCipherText.size() == hitlsCipherText.size());
            if (osCipherText.size() > 0) {
                RC_ASSERT(std::memcmp(osCipherText.data(), hitlsCipherText.data(), osCipherText.size()) == 0);
            }
        });

    return 0;
}