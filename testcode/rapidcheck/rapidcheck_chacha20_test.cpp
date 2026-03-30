/**
 * @file rapidcheck_chacha20_test.cpp
 * @brief RapidCheck property-based tests for ChaCha20-Poly1305 AEAD cipher
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_eal_cipher.h"
#include "crypt_errno.h"
#include "crypt_algid.h"

using namespace rc;

int main() {
    /**
     * @test ChaCha20-Poly1305 encrypt-decrypt roundtrip
     * @property decrypt(encrypt(plaintext)) == plaintext
     * @generalizes SDV_CRYPTO_CHACHA20_POLY1305_API_TC001 - ChaCha20-Poly1305 encryption tests
     * @see testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
     */
    rc::check("ChaCha20-Poly1305 encrypt-decrypt roundtrip",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto nonce = *gen::container<std::vector<uint8_t>>(12, gen::arbitrary<uint8_t>());
            auto aad = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(64, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, key.data(), 32, nonce.data(), 12, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherInit(decCtx, key.data(), 32, nonce.data(), 12, false);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_SET_AAD, aad.data(), aad.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad.data(), aad.size());
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext(80);
            std::vector<uint8_t> decrypted(64);
            uint32_t outLen = 64;
            
            ret = CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), 64, ciphertext.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            uint32_t tagLen = 16;
            ret = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, ciphertext.data() + 64, tagLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            ret = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            outLen = 64;
            ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), 64, decrypted.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted.data(), 64) == 0);
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    /**
     * @test ChaCha20-Poly1305 different keys produce different ciphertexts
     * @property For distinct keys, encrypt(p, k1) != encrypt(p, k2)
     * @generalizes Key sensitivity test
     * @see testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
     */
    rc::check("ChaCha20-Poly1305 different keys produce different ciphertexts",
        []() {
            auto key1 = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto key2 = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto nonce = *gen::container<std::vector<uint8_t>>(12, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            RC_PRE(key1 != key2);
            
            CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            CRYPT_EAL_CipherCtx *ctx2 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_CipherInit(ctx1, key1.data(), 32, nonce.data(), 12, true);
            CRYPT_EAL_CipherInit(ctx2, key2.data(), 32, nonce.data(), 12, true);
            
            uint8_t ciphertext1[48], ciphertext2[48];
            uint32_t outLen = 32;
            
            CRYPT_EAL_CipherUpdate(ctx1, plaintext.data(), 32, ciphertext1, &outLen);
            outLen = 32;
            CRYPT_EAL_CipherUpdate(ctx2, plaintext.data(), 32, ciphertext2, &outLen);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 32) != 0);
            
            CRYPT_EAL_CipherFreeCtx(ctx1);
            CRYPT_EAL_CipherFreeCtx(ctx2);
        });

    /**
     * @test ChaCha20-Poly1305 different nonces produce different ciphertexts
     * @property For distinct nonces, encrypt(p, k, n1) != encrypt(p, k, n2)
     * @generalizes Nonce sensitivity test
     * @see testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
     */
    rc::check("ChaCha20-Poly1305 different nonces produce different ciphertexts",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto nonce1 = *gen::container<std::vector<uint8_t>>(12, gen::arbitrary<uint8_t>());
            auto nonce2 = *gen::container<std::vector<uint8_t>>(12, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            RC_PRE(nonce1 != nonce2);
            
            CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            CRYPT_EAL_CipherCtx *ctx2 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_CipherInit(ctx1, key.data(), 32, nonce1.data(), 12, true);
            CRYPT_EAL_CipherInit(ctx2, key.data(), 32, nonce2.data(), 12, true);
            
            uint8_t ciphertext1[48], ciphertext2[48];
            uint32_t outLen = 32;
            
            CRYPT_EAL_CipherUpdate(ctx1, plaintext.data(), 32, ciphertext1, &outLen);
            outLen = 32;
            CRYPT_EAL_CipherUpdate(ctx2, plaintext.data(), 32, ciphertext2, &outLen);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 32) != 0);
            
            CRYPT_EAL_CipherFreeCtx(ctx1);
            CRYPT_EAL_CipherFreeCtx(ctx2);
        });

    /**
     * @test ChaCha20-Poly1305 tag verification
     * @property Wrong tag causes decryption failure
     * @generalizes Authentication test
     * @see testcode/sdv/testcase/crypto/chacha-poly/test_suite_sdv_eal_chachapoly.c
     */
    rc::check("ChaCha20-Poly1305 wrong tag causes decryption failure",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto nonce = *gen::container<std::vector<uint8_t>>(12, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_CHACHA20_POLY1305);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            CRYPT_EAL_CipherInit(encCtx, key.data(), 32, nonce.data(), 12, true);
            CRYPT_EAL_CipherInit(decCtx, key.data(), 32, nonce.data(), 12, false);
            
            std::vector<uint8_t> ciphertext(48);
            uint32_t outLen = 32;
            
            CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), 32, ciphertext.data(), &outLen);
            
            uint32_t tagLen = 16;
            CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, ciphertext.data() + 32, tagLen);
            
            ciphertext[32] ^= 0xFF;
            
            CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAGLEN, &tagLen, sizeof(tagLen));
            
            std::vector<uint8_t> decrypted(32);
            outLen = 32;
            int32_t ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), 32, decrypted.data(), &outLen);
            
            RC_ASSERT(ret != CRYPT_SUCCESS);
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    return 0;
}