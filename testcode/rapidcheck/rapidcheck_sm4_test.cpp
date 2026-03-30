/**
 * @file rapidcheck_sm4_test.cpp
 * @brief RapidCheck property-based tests for SM4 encryption
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c
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
     * @test SM4 ECB encrypt-decrypt roundtrip
     * @property decrypt(encrypt(plaintext)) == plaintext
     * @generalizes SDV_CRYPTO_SM4_INIT_API_TC001 - SM4 encryption tests
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:70-95
     */
    rc::check("SM4 ECB encrypt-decrypt roundtrip",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, key.data(), 16, nullptr, 0, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherInit(decCtx, key.data(), 16, nullptr, 0, false);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext(32);
            std::vector<uint8_t> decrypted(32);
            uint32_t outLen = 32;
            
            ret = CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), 32, ciphertext.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            outLen = 32;
            ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), 32, decrypted.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted.data(), 32) == 0);
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    /**
     * @test SM4 CBC encrypt-decrypt roundtrip
     * @property decrypt(encrypt(plaintext)) == plaintext
     * @generalizes SDV_CRYPTO_SM4_INIT_API_TC002 - SM4 CBC tests
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c:119-150
     */
    rc::check("SM4 CBC encrypt-decrypt roundtrip",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, key.data(), 16, iv.data(), 16, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherInit(decCtx, key.data(), 16, iv.data(), 16, false);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext(48);
            std::vector<uint8_t> decrypted(48);
            uint32_t outLen = 48, finalLen = 0;
            
            ret = CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), 32, ciphertext.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherFinal(encCtx, ciphertext.data() + outLen, &finalLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            uint32_t totalLen = outLen + finalLen;
            outLen = 48;
            finalLen = 0;
            
            ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), totalLen, decrypted.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherFinal(decCtx, decrypted.data() + outLen, &finalLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted.data(), 32) == 0);
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    /**
     * @test SM4 encryption is deterministic
     * @property encrypt(plaintext, key) == encrypt(plaintext, key)
     * @generalizes Determinism test
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c
     */
    rc::check("SM4 ECB encryption is deterministic",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_CipherInit(ctx, key.data(), 16, nullptr, 0, true);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            uint32_t outLen = 16;
            
            CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), 16, ciphertext1, &outLen);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherInit(ctx, key.data(), 16, nullptr, 0, true);
            
            outLen = 16;
            CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), 16, ciphertext2, &outLen);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) == 0);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test SM4 different keys produce different ciphertexts
     * @property For distinct keys, encrypt(p, k1) != encrypt(p, k2)
     * @generalizes Key sensitivity test
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c
     */
    rc::check("SM4 different keys produce different ciphertexts",
        []() {
            auto key1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto key2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(key1 != key2);
            
            CRYPT_EAL_CipherCtx *ctx1 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            CRYPT_EAL_CipherCtx *ctx2 = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            RC_PRE(ctx1 != nullptr);
            RC_PRE(ctx2 != nullptr);
            
            CRYPT_EAL_CipherInit(ctx1, key1.data(), 16, nullptr, 0, true);
            CRYPT_EAL_CipherInit(ctx2, key2.data(), 16, nullptr, 0, true);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            uint32_t outLen = 16;
            
            CRYPT_EAL_CipherUpdate(ctx1, plaintext.data(), 16, ciphertext1, &outLen);
            CRYPT_EAL_CipherUpdate(ctx2, plaintext.data(), 16, ciphertext2, &outLen);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) != 0);
            
            CRYPT_EAL_CipherFreeCtx(ctx1);
            CRYPT_EAL_CipherFreeCtx(ctx2);
        });

    /**
     * @test SM4 different plaintexts produce different ciphertexts
     * @property For distinct plaintexts, encrypt(p1, k) != encrypt(p2, k)
     * @generalizes Plaintext sensitivity test
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c
     */
    rc::check("SM4 different plaintexts produce different ciphertexts",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(plaintext1 != plaintext2);
            
            CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_ECB);
            RC_PRE(ctx != nullptr);
            
            CRYPT_EAL_CipherInit(ctx, key.data(), 16, nullptr, 0, true);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            uint32_t outLen = 16;
            
            CRYPT_EAL_CipherUpdate(ctx, plaintext1.data(), 16, ciphertext1, &outLen);
            
            CRYPT_EAL_CipherDeinit(ctx);
            CRYPT_EAL_CipherInit(ctx, key.data(), 16, nullptr, 0, true);
            
            CRYPT_EAL_CipherUpdate(ctx, plaintext2.data(), 16, ciphertext2, &outLen);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) != 0);
            
            CRYPT_EAL_CipherFreeCtx(ctx);
        });

    /**
     * @test SM4 CTR mode encrypt-decrypt roundtrip
     * @property decrypt(encrypt(plaintext)) == plaintext
     * @generalizes SDV_CRYPTO_SM4_CTR tests
     * @see testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c
     */
    rc::check("SM4 CTR encrypt-decrypt roundtrip",
        []() {
            auto key = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto iv = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            
            CRYPT_EAL_CipherCtx *encCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CTR);
            CRYPT_EAL_CipherCtx *decCtx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CTR);
            RC_PRE(encCtx != nullptr);
            RC_PRE(decCtx != nullptr);
            
            int32_t ret = CRYPT_EAL_CipherInit(encCtx, key.data(), 16, iv.data(), 16, true);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            ret = CRYPT_EAL_CipherInit(decCtx, key.data(), 16, iv.data(), 16, false);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> ciphertext(32);
            std::vector<uint8_t> decrypted(32);
            uint32_t outLen = 32;
            
            ret = CRYPT_EAL_CipherUpdate(encCtx, plaintext.data(), 32, ciphertext.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            outLen = 32;
            ret = CRYPT_EAL_CipherUpdate(decCtx, ciphertext.data(), 32, decrypted.data(), &outLen);
            RC_ASSERT(ret == CRYPT_SUCCESS);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted.data(), 32) == 0);
            
            CRYPT_EAL_CipherFreeCtx(encCtx);
            CRYPT_EAL_CipherFreeCtx(decCtx);
        });

    return 0;
}