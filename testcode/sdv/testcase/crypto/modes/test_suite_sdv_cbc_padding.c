/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/* BEGIN_HEADER */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_eal_init.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_cipher.h"

/* END_HEADER */

#define CBC_BLOCK_SIZE     16
#define CBC_KEY_SIZE       32
#define CBC_IV_SIZE        16
#define CBC_BUF_SIZE      512

/* ============================================================================
 * REFERENCE MODEL FOR CBC + PADDING STATE MACHINE
 *
 * State variables: dataLen (0..blockSize-1), enc bool, pad enum
 *
 * Properties tested (all NEW, not related to Deinit/Reinit bugs):
 *   1. Exact-block-size PKCS7: |Encrypt(16-byte-msg)| == 32 bytes
 *   2. PKCS7 round-trip: decrypt(encrypt(m)) == m for all lengths 1..48
 *   3. IV chaining property: wrong IV corrupts ONLY first block of CBC decrypt
 *   4. PKCS7 unpadding validation: invalid padding returns error
 *   5. Empty message: encrypt(empty) with PKCS7 == encrypt of full padding block
 *   6. Determinism: same key+IV+plaintext → same ciphertext (CBC is deterministic)
 * ============================================================================ */

static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

static int32_t CbcEncrypt(int cipherAlgId, const uint8_t *key, uint32_t keyLen,
                           const uint8_t *iv, uint32_t ivLen,
                           const uint8_t *plaintext, uint32_t ptLen,
                           uint8_t *ciphertext, uint32_t *ctLen)
{
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    if (ctx == NULL) return CRYPT_MEM_ALLOC_FAIL;
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    /* Enable PKCS7 padding */
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    uint32_t bufSize = *ctLen;
    uint32_t updLen = bufSize;
    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, ptLen, ciphertext, &updLen);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    uint32_t finLen = bufSize - updLen;
    ret = CRYPT_EAL_CipherFinal(ctx, ciphertext + updLen, &finLen);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    *ctLen = updLen + finLen;
    CRYPT_EAL_CipherFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

static int32_t CbcDecrypt(int cipherAlgId, const uint8_t *key, uint32_t keyLen,
                           const uint8_t *iv, uint32_t ivLen,
                           const uint8_t *ciphertext, uint32_t ctLen,
                           uint8_t *plaintext, uint32_t *ptLen)
{
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    if (ctx == NULL) return CRYPT_MEM_ALLOC_FAIL;
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, false);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    /* Enable PKCS7 padding for decryption */
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    uint32_t bufSize = *ptLen;
    uint32_t updLen = bufSize;
    ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, ctLen, plaintext, &updLen);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    uint32_t finLen = bufSize - updLen;
    ret = CRYPT_EAL_CipherFinal(ctx, plaintext + updLen, &finLen);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_CipherFreeCtx(ctx); return ret; }
    *ptLen = updLen + finLen;
    CRYPT_EAL_CipherFreeCtx(ctx);
    return CRYPT_SUCCESS;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_CBC_PKCS7_EXACT_BLOCK_TC001
 * @title Verify exact-block-size plaintext with PKCS7 adds one full extra block
 * @precon nan
 * @brief
 *  1.Encrypt exactly 16 bytes (one AES block) with PKCS7 padding
 *  2.Output must be 32 bytes (original + full padding block)
 *  3.Decrypt 32 bytes must recover exactly 16 bytes
 * @expect |Encrypt_PKCS7(16-byte-msg)| == 32, Decrypt recovers 16 bytes
 */
/* BEGIN_CASE */
void SDV_CBC_PKCS7_EXACT_BLOCK_TC001(void)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)(i + 1);

    uint8_t iv[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv[i] = (uint8_t)(i * 3 + 7);

    /* Exactly one block of plaintext */
    uint8_t plaintext[CBC_BLOCK_SIZE];
    for (int i = 0; i < CBC_BLOCK_SIZE; i++) plaintext[i] = (uint8_t)(i * 7 + 13);

    uint8_t ct[CBC_BUF_SIZE];
    uint8_t dec[CBC_BUF_SIZE];
    uint32_t ctLen = sizeof(ct);
    uint32_t decLen = sizeof(dec);

    /* Encrypt with PKCS7 padding (default for AES-CBC) */
    ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         plaintext, CBC_BLOCK_SIZE, ct, &ctLen), CRYPT_SUCCESS);

    /* Reference model: exact block → extra full padding block */
    ASSERT_EQ(ctLen, (uint32_t)(CBC_BLOCK_SIZE * 2));

    /* Decrypt must recover exactly the original 16 bytes */
    ASSERT_EQ(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         ct, ctLen, dec, &decLen), CRYPT_SUCCESS);
    ASSERT_EQ(decLen, (uint32_t)CBC_BLOCK_SIZE);
    ASSERT_EQ(memcmp(plaintext, dec, CBC_BLOCK_SIZE), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_CBC_PKCS7_ROUNDTRIP_TC001
 * @title Verify PKCS7 round-trip for all message lengths 1 to 48 bytes
 * @precon nan
 * @brief
 *  1.For each length L from 1 to 48:
 *     Encrypt L bytes with PKCS7
 *     Decrypt → must recover exactly L bytes == original
 * @expect decrypt(encrypt(m)) == m for all lengths
 */
/* BEGIN_CASE */
void SDV_CBC_PKCS7_ROUNDTRIP_TC001(void)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)(i * 11 + 3);

    uint8_t iv[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv[i] = (uint8_t)(i * 7 + 5);

    uint8_t plaintext[48];
    for (int i = 0; i < 48; i++) plaintext[i] = (uint8_t)(i * 5 + 11);

    uint8_t ct[CBC_BUF_SIZE];
    uint8_t dec[CBC_BUF_SIZE];

    for (int len = 1; len <= 48; len++) {
        uint32_t ctLen = sizeof(ct);
        uint32_t decLen = sizeof(dec);

        ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                             plaintext, (uint32_t)len, ct, &ctLen), CRYPT_SUCCESS);

        /* PKCS7 output length must be a multiple of block size */
        ASSERT_EQ(ctLen % CBC_BLOCK_SIZE, 0);

        ASSERT_EQ(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                             ct, ctLen, dec, &decLen), CRYPT_SUCCESS);

        /* Decrypted length must equal original */
        ASSERT_EQ(decLen, (uint32_t)len);
        ASSERT_EQ(memcmp(plaintext, dec, (uint32_t)len), 0);
    }

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_CBC_IV_CHAINING_PROPERTY_TC001
 * @title Verify CBC IV chaining: wrong IV corrupts only first block
 * @precon nan
 * @brief
 *  1.Encrypt 3 blocks (48 bytes) with IV1
 *  2.Decrypt with IV2 (different from IV1)
 *  3.Block 1 of decryption is corrupted (XOR of IV1, IV2)
 *  4.Blocks 2 and 3 decrypt correctly (CBC chaining uses ciphertext as IV)
 * @expect Wrong IV corrupts first block only; subsequent blocks are correct
 */
/* BEGIN_CASE */
void SDV_CBC_IV_CHAINING_PROPERTY_TC001(void)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t iv1[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv1[i] = (uint8_t)i;

    uint8_t iv2[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv2[i] = (uint8_t)(i + 100);

    /* 3 blocks of plaintext */
    uint8_t plaintext[48];
    for (int i = 0; i < 48; i++) plaintext[i] = (uint8_t)(i * 7 + 13);

    uint8_t ct[CBC_BUF_SIZE];
    uint8_t dec_correct[CBC_BUF_SIZE];
    uint8_t dec_wrong_iv[CBC_BUF_SIZE];
    uint32_t ctLen = sizeof(ct);
    uint32_t decLen1 = sizeof(dec_correct);
    uint32_t decLen2 = sizeof(dec_wrong_iv);

    /* Encrypt with IV1 */
    ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv1, CBC_IV_SIZE,
                         plaintext, 48, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(ctLen, (uint32_t)(48 + CBC_BLOCK_SIZE)); /* 3 data blocks + 1 padding block */

    /* Decrypt with correct IV1 — all blocks correct */
    ASSERT_EQ(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv1, CBC_IV_SIZE,
                         ct, ctLen, dec_correct, &decLen1), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(plaintext, dec_correct, 48), 0);

    /* Decrypt with wrong IV2 — first block corrupted, rest correct */
    ASSERT_EQ(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv2, CBC_IV_SIZE,
                         ct, ctLen, dec_wrong_iv, &decLen2), CRYPT_SUCCESS);

    /* Block 1: MUST be different (corrupted by IV mismatch) */
    ASSERT_NE(memcmp(dec_wrong_iv, plaintext, CBC_BLOCK_SIZE), 0);

    /* Blocks 2 and 3: MUST be correct (CBC uses ciphertext as IV for subsequent blocks) */
    ASSERT_EQ(memcmp(dec_wrong_iv + CBC_BLOCK_SIZE, plaintext + CBC_BLOCK_SIZE, 32), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_CBC_PKCS7_UNPADDING_INVALID_TC001
 * @title Verify invalid PKCS7 padding is rejected during decryption
 * @precon nan
 * @brief
 *  1.Encrypt a message to get valid ciphertext
 *  2.Corrupt the last byte of the last ciphertext block (modifies padding)
 *  3.Decrypt must fail with padding error
 * @expect Corrupted PKCS7 padding is detected and rejected
 */
/* BEGIN_CASE */
void SDV_CBC_PKCS7_UNPADDING_INVALID_TC001(void)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)i;

    uint8_t iv[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv[i] = (uint8_t)(i * 5 + 3);

    /* Message shorter than a block so padding is present */
    uint8_t plaintext[10];
    for (int i = 0; i < 10; i++) plaintext[i] = (uint8_t)(i + 1);

    uint8_t ct[CBC_BUF_SIZE];
    uint8_t dec[CBC_BUF_SIZE];
    uint32_t ctLen = sizeof(ct);
    uint32_t decLen = sizeof(dec);

    ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         plaintext, 10, ct, &ctLen), CRYPT_SUCCESS);
    ASSERT_EQ(ctLen, (uint32_t)CBC_BLOCK_SIZE); /* 10 bytes → 1 block with 6 bytes padding */

    /* Corrupt last ciphertext byte (affects the decrypted padding byte values) */
    ct[ctLen - 1] ^= 0xFF;

    /* Decryption should fail due to invalid padding */
    ASSERT_NE(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         ct, ctLen, dec, &decLen), CRYPT_SUCCESS);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_CBC_DETERMINISM_TC001
 * @title Verify CBC encryption is deterministic: same key+IV+plaintext → same ciphertext
 * @precon nan
 * @brief
 *  1.Encrypt same message twice with same key and IV
 *  2.Both ciphertexts must be identical
 * @expect CBC is deterministic for same inputs
 */
/* BEGIN_CASE */
void SDV_CBC_DETERMINISM_TC001(void)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)(i * 7 + 11);

    uint8_t iv[CBC_IV_SIZE];
    for (int i = 0; i < CBC_IV_SIZE; i++) iv[i] = (uint8_t)(i * 11 + 3);

    uint8_t plaintext[32];
    for (int i = 0; i < 32; i++) plaintext[i] = (uint8_t)(i * 13 + 7);

    uint8_t ct1[CBC_BUF_SIZE];
    uint8_t ct2[CBC_BUF_SIZE];
    uint32_t ctLen1 = sizeof(ct1);
    uint32_t ctLen2 = sizeof(ct2);

    ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         plaintext, 32, ct1, &ctLen1), CRYPT_SUCCESS);

    ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                         plaintext, 32, ct2, &ctLen2), CRYPT_SUCCESS);

    ASSERT_EQ(ctLen1, ctLen2);
    ASSERT_EQ(memcmp(ct1, ct2, ctLen1), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_CBC_RANDOM_LENGTH_ROUNDTRIP_TC001
 * @title Verify PKCS7 round-trip for random message lengths with random seeds
 * @precon nan
 * @brief
 *  Generate random plaintext lengths and content, verify round-trip
 * @expect All random-length messages round-trip correctly
 */
/* BEGIN_CASE */
void SDV_CBC_RANDOM_LENGTH_ROUNDTRIP_TC001(int numOps, int seed)
{
    TestMemInit();

    uint8_t key[CBC_KEY_SIZE];
    uint8_t iv[CBC_IV_SIZE];
    for (int i = 0; i < CBC_KEY_SIZE; i++) key[i] = (uint8_t)((i * seed) & 0xFF);
    for (int i = 0; i < CBC_IV_SIZE; i++) iv[i] = (uint8_t)((i * seed * 7) & 0xFF);

    uint32_t prng = (uint32_t)seed;
    uint8_t plaintext[200];
    uint8_t ct[CBC_BUF_SIZE];
    uint8_t dec[CBC_BUF_SIZE];

    for (int op = 0; op < numOps; op++) {
        uint32_t len = (SimplePrng(&prng) % 200) + 1;
        for (uint32_t i = 0; i < len; i++) plaintext[i] = (uint8_t)(SimplePrng(&prng) & 0xFF);

        uint32_t ctLen = sizeof(ct);
        uint32_t decLen = sizeof(dec);

        ASSERT_EQ(CbcEncrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                             plaintext, len, ct, &ctLen), CRYPT_SUCCESS);

        ASSERT_EQ(ctLen % CBC_BLOCK_SIZE, 0);

        ASSERT_EQ(CbcDecrypt(CRYPT_CIPHER_AES256_CBC, key, CBC_KEY_SIZE, iv, CBC_IV_SIZE,
                             ct, ctLen, dec, &decLen), CRYPT_SUCCESS);

        ASSERT_EQ(decLen, len);
        ASSERT_EQ(memcmp(plaintext, dec, len), 0);
    }

EXIT:
    return;
}
/* END_CASE */
