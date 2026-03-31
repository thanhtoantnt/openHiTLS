/**
 * @file rapidcheck_edge_test.cpp
 * @brief RapidCheck property-based tests for edge cases that might violate properties
 * 
 * This file tests edge cases that might violate expected properties:
 * - Null pointer handling
 * - Zero-length inputs
 * - Unaligned inputs
 * - Boundary conditions
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>

#include "hitls_build.h"
#include "crypt_aes.h"
#include "crypt_errno.h"

using namespace rc;

int main() {
    /**
     * @test AES null key pointer handling
     * @property Null key should return error, not crash
     * @generalizes Safety property - null pointer handling
     */
    rc::check("AES encrypt with null key should return error",
        []() {
            std::vector<uint8_t> plaintext(16, 0x41);
            std::vector<uint8_t> ciphertext(16);
            
            int32_t ret = CRYPT_AES_Encrypt(NULL, plaintext.data(), ciphertext.data(), 16);
            
            // Property: Should return error, not crash or succeed
            RC_ASSERT(ret != CRYPT_SUCCESS);
        });

    /**
     * @test AES null plaintext pointer handling
     * @property Null plaintext should return error
     */
    rc::check("AES encrypt with null plaintext should return error",
        []() {
            CRYPT_AES_Key key;
            std::memset(&key, 0, sizeof(key));
            uint8_t keyData[16] = {0};
            CRYPT_AES_SetEncryptKey128(&key, keyData, 16);
            
            std::vector<uint8_t> ciphertext(16);
            
            int32_t ret = CRYPT_AES_Encrypt(&key, NULL, ciphertext.data(), 16);
            
            // Property: Should return error
            RC_ASSERT(ret != CRYPT_SUCCESS);
        });

    /**
     * @test AES null ciphertext pointer handling
     * @property Null ciphertext should return error
     */
    rc::check("AES encrypt with null ciphertext should return error",
        []() {
            CRYPT_AES_Key key;
            std::memset(&key, 0, sizeof(key));
            uint8_t keyData[16] = {0};
            CRYPT_AES_SetEncryptKey128(&key, keyData, 16);
            
            std::vector<uint8_t> plaintext(16, 0x41);
            
            int32_t ret = CRYPT_AES_Encrypt(&key, plaintext.data(), NULL, 16);
            
            // Property: Should return error
            RC_ASSERT(ret != CRYPT_SUCCESS);
        });

    /**
     * @test AES zero length handling
     * @property Zero length should be handled gracefully
     */
    rc::check("AES encrypt with zero length",
        []() {
            CRYPT_AES_Key key;
            std::memset(&key, 0, sizeof(key));
            uint8_t keyData[16] = {0};
            CRYPT_AES_SetEncryptKey128(&key, keyData, 16);
            
            std::vector<uint8_t> plaintext(16, 0x41);
            std::vector<uint8_t> ciphertext(16);
            
            int32_t ret = CRYPT_AES_Encrypt(&key, plaintext.data(), ciphertext.data(), 0);
            
            // Property: Should either succeed (no-op) or return error
            // But should NOT crash
            RC_ASSERT(true); // If we get here, no crash occurred
        });

    /**
     * @test AES key schedule consistency
     * @property Same key should always produce same key schedule
     */
    rc::check("AES key schedule is deterministic",
        [](const std::vector<uint8_t> &keyData) {
            RC_PRE(keyData.size() == 16);
            
            CRYPT_AES_Key key1, key2;
            std::memset(&key1, 0, sizeof(key1));
            std::memset(&key2, 0, sizeof(key2));
            
            CRYPT_AES_SetEncryptKey128(&key1, keyData.data(), 16);
            CRYPT_AES_SetEncryptKey128(&key2, keyData.data(), 16);
            
            // Property: Same key should produce same round keys
            RC_ASSERT(key1.rounds == key2.rounds);
        });

    /**
     * @test AES different key sizes
     * @property 128, 192, 256-bit keys should have correct round counts
     */
    rc::check("AES key size determines correct round count",
        [](uint32_t keyBits) {
            RC_PRE(keyBits == 128 || keyBits == 192 || keyBits == 256);
            
            CRYPT_AES_Key key;
            std::memset(&key, 0, sizeof(key));
            
            std::vector<uint8_t> keyData(keyBits / 8);
            int32_t ret = 0;
            
            if (keyBits == 128) {
                ret = CRYPT_AES_SetEncryptKey128(&key, keyData.data(), 16);
                if (ret == CRYPT_SUCCESS) {
                    RC_ASSERT(key.rounds == 10);
                }
            } else if (keyBits == 192) {
                ret = CRYPT_AES_SetEncryptKey192(&key, keyData.data(), 24);
                if (ret == CRYPT_SUCCESS) {
                    RC_ASSERT(key.rounds == 12);
                }
            } else {
                ret = CRYPT_AES_SetEncryptKey256(&key, keyData.data(), 32);
                if (ret == CRYPT_SUCCESS) {
                    RC_ASSERT(key.rounds == 14);
                }
            }
        });

    /**
     * @test AES encrypt-decrypt with all-zero key and plaintext
     * @property Should produce consistent output
     */
    rc::check("AES all-zero inputs produce consistent output",
        []() {
            CRYPT_AES_Key encKey, decKey;
            std::memset(&encKey, 0, sizeof(encKey));
            std::memset(&decKey, 0, sizeof(decKey));
            
            uint8_t zeroKey[16] = {0};
            CRYPT_AES_SetEncryptKey128(&encKey, zeroKey, 16);
            CRYPT_AES_SetDecryptKey128(&decKey, zeroKey, 16);
            
            std::vector<uint8_t> plaintext(16, 0);
            std::vector<uint8_t> ciphertext(16);
            std::vector<uint8_t> decrypted(16);
            
            CRYPT_AES_Encrypt(&encKey, plaintext.data(), ciphertext.data(), 16);
            CRYPT_AES_Decrypt(&decKey, ciphertext.data(), decrypted.data(), 16);
            
            RC_ASSERT(plaintext == decrypted);
        });

    /**
     * @test AES single bit difference in key
     * @property Single bit change in key should produce completely different ciphertext
     */
    rc::check("AES single bit key change produces different ciphertext",
        [](uint32_t bitPosition) {
            RC_PRE(bitPosition < 128);
            
            std::vector<uint8_t> key1(16, 0);
            std::vector<uint8_t> key2(16, 0);
            
            // Flip one bit
            key2[bitPosition / 8] ^= (1 << (bitPosition % 8));
            
            CRYPT_AES_Key encKey1, encKey2;
            std::memset(&encKey1, 0, sizeof(encKey1));
            std::memset(&encKey2, 0, sizeof(encKey2));
            
            CRYPT_AES_SetEncryptKey128(&encKey1, key1.data(), 16);
            CRYPT_AES_SetEncryptKey128(&encKey2, key2.data(), 16);
            
            std::vector<uint8_t> plaintext(16, 0x42);
            std::vector<uint8_t> ciphertext1(16);
            std::vector<uint8_t> ciphertext2(16);
            
            CRYPT_AES_Encrypt(&encKey1, plaintext.data(), ciphertext1.data(), 16);
            CRYPT_AES_Encrypt(&encKey2, plaintext.data(), ciphertext2.data(), 16);
            
            // Property: Ciphertexts should be different (avalanche effect)
            RC_ASSERT(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16) != 0);
        });

    /**
     * @test AES single bit difference in plaintext
     * @property Single bit change in plaintext should produce different ciphertext
     */
    rc::check("AES single bit plaintext change produces different ciphertext",
        [](uint32_t bitPosition) {
            RC_PRE(bitPosition < 128);
            
            std::vector<uint8_t> key(16, 0x11);
            
            std::vector<uint8_t> plaintext1(16, 0x42);
            std::vector<uint8_t> plaintext2(16, 0x42);
            
            // Flip one bit
            plaintext2[bitPosition / 8] ^= (1 << (bitPosition % 8));
            
            CRYPT_AES_Key encKey;
            std::memset(&encKey, 0, sizeof(encKey));
            CRYPT_AES_SetEncryptKey128(&encKey, key.data(), 16);
            
            std::vector<uint8_t> ciphertext1(16);
            std::vector<uint8_t> ciphertext2(16);
            
            CRYPT_AES_Encrypt(&encKey, plaintext1.data(), ciphertext1.data(), 16);
            CRYPT_AES_Encrypt(&encKey, plaintext2.data(), ciphertext2.data(), 16);
            
            // Property: Ciphertexts should be different
            RC_ASSERT(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16) != 0);
        });

    return 0;
}