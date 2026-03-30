/**
 * @file rapidcheck_aes_test.cpp
 * @brief RapidCheck property-based tests for AES encryption
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
 * - testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_cipher.c
 * 
 * Property-based testing automatically generates thousands of random test cases
 * to find edge cases that fixed unit tests might miss.
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_aes.h"

using namespace rc;

int main() {
    /**
     * @test AES single block encrypt-decrypt roundtrip (128-bit key)
     * @property For all 16-byte keys and 16-byte plaintexts,
     *           decrypt(encrypt(plaintext, key), key) == plaintext
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001 - Key initialization tests
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_DECRYPT_API_TC001 - Basic encrypt/decrypt
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:100-150
     */
    rc::check("AES single block encrypt-decrypt roundtrip (128-bit key)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_AES_Key encKey, decKey;
            std::memset(&encKey, 0, sizeof(encKey));
            std::memset(&decKey, 0, sizeof(decKey));
            
            int ret = CRYPT_AES_SetEncryptKey128(&encKey, keyData.data(), 16);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_SetDecryptKey128(&decKey, keyData.data(), 16);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext[16];
            uint8_t decrypted[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext, 16);
            RC_ASSERT(ret == 0);
            
            ret = CRYPT_AES_Decrypt(&decKey, ciphertext, decrypted, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted, 16) == 0);
            
            CRYPT_AES_Clean(&encKey);
            CRYPT_AES_Clean(&decKey);
        });

    /**
     * @test AES single block encrypt-decrypt roundtrip (192-bit key)
     * @property For all 24-byte keys and 16-byte plaintexts,
     *           decrypt(encrypt(plaintext, key), key) == plaintext
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001 - Key initialization tests (192-bit)
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("AES single block encrypt-decrypt roundtrip (192-bit key)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(24, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_AES_Key encKey, decKey;
            std::memset(&encKey, 0, sizeof(encKey));
            std::memset(&decKey, 0, sizeof(decKey));
            
            int ret = CRYPT_AES_SetEncryptKey192(&encKey, keyData.data(), 24);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_SetDecryptKey192(&decKey, keyData.data(), 24);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext[16];
            uint8_t decrypted[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext, 16);
            RC_ASSERT(ret == 0);
            
            ret = CRYPT_AES_Decrypt(&decKey, ciphertext, decrypted, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted, 16) == 0);
            
            CRYPT_AES_Clean(&encKey);
            CRYPT_AES_Clean(&decKey);
        });

    /**
     * @test AES single block encrypt-decrypt roundtrip (256-bit key)
     * @property For all 32-byte keys and 16-byte plaintexts,
     *           decrypt(encrypt(plaintext, key), key) == plaintext
     * @generalizes SDV_CRYPTO_AES_INIT_API_TC001 - Key initialization tests (256-bit)
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("AES single block encrypt-decrypt roundtrip (256-bit key)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(32, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_AES_Key encKey, decKey;
            std::memset(&encKey, 0, sizeof(encKey));
            std::memset(&decKey, 0, sizeof(decKey));
            
            int ret = CRYPT_AES_SetEncryptKey256(&encKey, keyData.data(), 32);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_SetDecryptKey256(&decKey, keyData.data(), 32);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext[16];
            uint8_t decrypted[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext, 16);
            RC_ASSERT(ret == 0);
            
            ret = CRYPT_AES_Decrypt(&decKey, ciphertext, decrypted, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(plaintext.data(), decrypted, 16) == 0);
            
            CRYPT_AES_Clean(&encKey);
            CRYPT_AES_Clean(&decKey);
        });

    /**
     * @test AES encryption produces different output for different plaintexts
     * @property For all keys and distinct plaintext pairs p1 != p2,
     *           encrypt(p1, key) != encrypt(p2, key)
     * @generalizes Tests the confusion property of AES
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("AES encryption produces different output for different plaintexts",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(plaintext1 != plaintext2);
            
            CRYPT_AES_Key encKey;
            std::memset(&encKey, 0, sizeof(encKey));
            
            int ret = CRYPT_AES_SetEncryptKey128(&encKey, keyData.data(), 16);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext1.data(), ciphertext1, 16);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_Encrypt(&encKey, plaintext2.data(), ciphertext2, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) != 0);
            
            CRYPT_AES_Clean(&encKey);
        });

    /**
     * @test AES encryption produces different output for same plaintext with different keys
     * @property For all distinct key pairs k1 != k2 and all plaintexts,
     *           encrypt(plaintext, k1) != encrypt(plaintext, k2)
     * @generalizes Tests that key choice affects ciphertext
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("AES encryption produces different output for same plaintext with different keys",
        []() {
            auto key1 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto key2 = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            RC_PRE(key1 != key2);
            
            CRYPT_AES_Key encKey1, encKey2;
            std::memset(&encKey1, 0, sizeof(encKey1));
            std::memset(&encKey2, 0, sizeof(encKey2));
            
            int ret = CRYPT_AES_SetEncryptKey128(&encKey1, key1.data(), 16);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_SetEncryptKey128(&encKey2, key2.data(), 16);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            
            ret = CRYPT_AES_Encrypt(&encKey1, plaintext.data(), ciphertext1, 16);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_Encrypt(&encKey2, plaintext.data(), ciphertext2, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) != 0);
            
            CRYPT_AES_Clean(&encKey1);
            CRYPT_AES_Clean(&encKey2);
        });

    /**
     * @test AES encryption is deterministic (same key + plaintext = same ciphertext)
     * @property For all keys and plaintexts,
     *           encrypt(plaintext, key) == encrypt(plaintext, key)
     * @generalizes SDV_CRYPTO_AES_ENCRYPT_DECRYPT_API_TC001 - Determinism test
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c:574
     */
    rc::check("AES encryption is deterministic (same key + plaintext = same ciphertext)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_AES_Key encKey;
            std::memset(&encKey, 0, sizeof(encKey));
            
            int ret = CRYPT_AES_SetEncryptKey128(&encKey, keyData.data(), 16);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext1[16], ciphertext2[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext1, 16);
            RC_ASSERT(ret == 0);
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext2, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(ciphertext1, ciphertext2, 16) == 0);
            
            CRYPT_AES_Clean(&encKey);
        });

    /**
     * @test AES ciphertext is different from plaintext (confusion)
     * @property For all keys and plaintexts, encrypt(plaintext, key) != plaintext
     * @generalizes Tests the confusion property - ciphertext should not reveal plaintext
     * @see testcode/sdv/testcase/crypto/aes/test_suite_sdv_eal_aes.c
     */
    rc::check("AES ciphertext is different from plaintext (confusion)",
        []() {
            auto keyData = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            auto plaintext = *gen::container<std::vector<uint8_t>>(16, gen::arbitrary<uint8_t>());
            
            CRYPT_AES_Key encKey;
            std::memset(&encKey, 0, sizeof(encKey));
            
            int ret = CRYPT_AES_SetEncryptKey128(&encKey, keyData.data(), 16);
            RC_ASSERT(ret == 0);
            
            uint8_t ciphertext[16];
            
            ret = CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext, 16);
            RC_ASSERT(ret == 0);
            
            RC_ASSERT(std::memcmp(plaintext.data(), ciphertext, 16) != 0);
            
            CRYPT_AES_Clean(&encKey);
        });

    return 0;
}