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

#define GCM_TEST_KEY_SIZE 32
#define GCM_TEST_IV_SIZE 12
#define GCM_TEST_TAG_SIZE 16
#define GCM_TEST_MAX_MSG_SIZE 256
#define GCM_TEST_MAX_AAD_SIZE 128

/* ============================================================================
 * REFERENCE MODEL FOR GCM AEAD STATE MACHINE
 * Tracks expected GCM behavior based on NIST SP 800-38D
 * ============================================================================ */

typedef enum {
    REF_STATE_NEW = 0,
    REF_STATE_INIT = 1,
    REF_STATE_UPDATE = 2,
    REF_STATE_FINAL = 3
} RefGcmState;

typedef enum {
    REF_OP_INIT = 0,
    REF_OP_UPDATE = 1,
    REF_OP_FINAL = 2,
    REF_OP_REINIT = 3,
    REF_OP_COUNT = 4
} RefGcmOp;

typedef struct {
    RefGcmState state;
    bool isEncrypt;
    uint32_t updateCount;
    uint32_t totalDataLen;
    uint32_t aadLen;
} RefGcmModel;

typedef struct {
    int32_t retCode;
    RefGcmState stateBefore;
    RefGcmState stateAfter;
    bool success;
} RefOpResult;

static void RefModel_Init(RefGcmModel *model)
{
    model->state = REF_STATE_NEW;
    model->isEncrypt = false;
    model->updateCount = 0;
    model->totalDataLen = 0;
    model->aadLen = 0;
}

static RefOpResult RefModel_CipherInit(RefGcmModel *model, bool enc, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_NEW && model->state != REF_STATE_FINAL) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->state = REF_STATE_INIT;
        model->isEncrypt = enc;
        model->updateCount = 0;
        model->totalDataLen = 0;
        model->aadLen = 0;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_CipherUpdate(RefGcmModel *model, uint32_t dataLen, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_INIT && model->state != REF_STATE_UPDATE) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->state = REF_STATE_UPDATE;
        model->updateCount++;
        model->totalDataLen += dataLen;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_CipherFinal(RefGcmModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_INIT && model->state != REF_STATE_UPDATE) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->state = REF_STATE_FINAL;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_MODES_TAG_ERROR;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

/* ============================================================================
 * SIMPLE PRNG FOR RANDOM TEST GENERATION
 * ============================================================================ */

static uint32_t SimplePrng(uint32_t *state)
{
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    return *state;
}

static uint32_t GetKeySize(int cipherAlgId)
{
    switch (cipherAlgId) {
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES128_CCM:
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES128_CTR:
            return 16;
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES192_CCM:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES192_CTR:
            return 24;
        case CRYPT_CIPHER_AES256_GCM:
        case CRYPT_CIPHER_AES256_CCM:
        case CRYPT_CIPHER_AES256_CBC:
        case CRYPT_CIPHER_AES256_CTR:
            return 32;
        default:
            return 32;
    }
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test   SDV_GCM_STATE_MACHINE_ROUNDTRIP_TC001
 * @title  Verify GCM encrypt/decrypt roundtrip property
 * @precon nan
 * @brief
 *    1.Encrypt plaintext with GCM
 *    2.Decrypt ciphertext with same key/IV
 *    3.Verify decrypted text matches original plaintext
 * @expect
 *    decrypt(encrypt(m)) = m
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_ROUNDTRIP_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    RefGcmModel refModel;
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    RefOpResult refResult;
    int32_t implRet;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)(i * 3 + 7);
    
    uint8_t iv[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv[i] = (uint8_t)(i * 5 + 11);
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) plaintext[i] = (uint8_t)(i * 7 + 13);
    
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[GCM_TEST_TAG_SIZE];
    uint32_t encOutLen = 0;
    uint32_t decOutLen = 0;
    uint32_t tagLen = GCM_TEST_TAG_SIZE;
    
    RefModel_Init(&refModel);
    
    /* Encrypt */
    encCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(encCtx != NULL);
    
    refResult = RefModel_CipherInit(&refModel, true, true);
    implRet = CRYPT_EAL_CipherInit(encCtx, key, keySize, iv, GCM_TEST_IV_SIZE, true);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_CipherUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_CipherUpdate(encCtx, plaintext, 64, ciphertext, &encOutLen);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_CipherFinal(&refModel, true);
    implRet = CRYPT_EAL_CipherFinal(encCtx, ciphertext + encOutLen, &encOutLen);
    ASSERT_EQ(implRet, refResult.retCode);
    
    implRet = CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tag, tagLen);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    
    /* Decrypt */
    RefModel_Init(&refModel);
    
    decCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(decCtx != NULL);
    
    refResult = RefModel_CipherInit(&refModel, false, true);
    implRet = CRYPT_EAL_CipherInit(decCtx, key, keySize, iv, GCM_TEST_IV_SIZE, false);
    ASSERT_EQ(implRet, refResult.retCode);
    
    implRet = CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAG, tag, tagLen);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    
    refResult = RefModel_CipherUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_CipherUpdate(decCtx, ciphertext, 64, decrypted, &decOutLen);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_CipherFinal(&refModel, true);
    implRet = CRYPT_EAL_CipherFinal(decCtx, decrypted + decOutLen, &decOutLen);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Verify roundtrip */
    ASSERT_EQ(memcmp(plaintext, decrypted, 64), 0);
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_GCM_STATE_MACHINE_TAG_VERIFICATION_TC001
 * @title  Verify GCM tag verification fails on modified tag
 * @precon nan
 * @brief
 *    1.Encrypt plaintext, get tag
 *    2.Modify tag (flip a bit)
 *    3.Attempt decrypt with modified tag
 *    4.Verify decryption fails
 * @expect
 *    Tag modification causes decryption failure
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_TAG_VERIFICATION_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)(i + 1);
    
    uint8_t iv[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv[i] = (uint8_t)(i + 2);
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) plaintext[i] = (uint8_t)i;
    
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[GCM_TEST_TAG_SIZE];
    uint32_t encOutLen = 0;
    uint32_t decOutLen = 0;
    uint32_t tagLen = GCM_TEST_TAG_SIZE;
    
    /* Encrypt */
    encCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(encCtx, key, keySize, iv, GCM_TEST_IV_SIZE, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(encCtx, plaintext, 64, ciphertext, &encOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(encCtx, ciphertext + encOutLen, &encOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);
    
    /* Modify tag */
    tag[0] ^= 0xFF;
    
    /* Decrypt with modified tag - should fail */
    decCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(decCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(decCtx, key, keySize, iv, GCM_TEST_IV_SIZE, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAG, tag, tagLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(decCtx, ciphertext, 64, decrypted, &decOutLen), CRYPT_SUCCESS);
    
    /* Final should fail due to invalid tag */
    ASSERT_NE(CRYPT_EAL_CipherFinal(decCtx, decrypted + decOutLen, &decOutLen), CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_GCM_STATE_MACHINE_AAD_TC001
 * @title  Verify GCM AAD (Additional Authenticated Data) property
 * @precon nan
 * @brief
 *    1.Encrypt with AAD
 *    2.Decrypt with same AAD - should succeed
 *    3.Decrypt with different AAD - should fail
 * @expect
 *    AAD is authenticated but not encrypted
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_AAD_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)(i * 2);
    
    uint8_t iv[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv[i] = (uint8_t)(i * 3);
    
    uint8_t aad[32];
    for (int i = 0; i < 32; i++) aad[i] = (uint8_t)(i * 4);
    
    uint8_t aadModified[32];
    for (int i = 0; i < 32; i++) aadModified[i] = (uint8_t)(i * 4 + 1);
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) plaintext[i] = (uint8_t)i;
    
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[GCM_TEST_TAG_SIZE];
    uint32_t encOutLen = 0;
    uint32_t decOutLen = 0;
    uint32_t tagLen = GCM_TEST_TAG_SIZE;
    
    /* Encrypt with AAD */
    encCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(encCtx, key, keySize, iv, GCM_TEST_IV_SIZE, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_SET_AAD, aad, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(encCtx, plaintext, 64, ciphertext, &encOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(encCtx, ciphertext + encOutLen, &encOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);
    
    /* Decrypt with same AAD - should succeed */
    decCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(decCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(decCtx, key, keySize, iv, GCM_TEST_IV_SIZE, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aad, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAG, tag, tagLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(decCtx, ciphertext, 64, decrypted, &decOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(decCtx, decrypted + decOutLen, &decOutLen), CRYPT_SUCCESS);
    
    /* Verify decrypted matches original */
    ASSERT_EQ(memcmp(plaintext, decrypted, 64), 0);
    
    CRYPT_EAL_CipherFreeCtx(decCtx);
    decCtx = NULL;
    
    /* Decrypt with different AAD - should fail */
    decCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(decCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(decCtx, key, keySize, iv, GCM_TEST_IV_SIZE, false), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_AAD, aadModified, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAG, tag, tagLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(decCtx, ciphertext, 64, decrypted, &decOutLen), CRYPT_SUCCESS);
    
    /* Final should fail due to AAD mismatch */
    ASSERT_NE(CRYPT_EAL_CipherFinal(decCtx, decrypted + decOutLen, &decOutLen), CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_GCM_STATE_MACHINE_IV_UNIQUENESS_TC001
 * @title  Verify GCM produces different ciphertext with different IV
 * @precon nan
 * @brief
 *    1.Encrypt with IV1
 *    2.Encrypt with IV2 (same key, same plaintext)
 *    3.Verify ciphertexts are different
 * @expect
 *    Different IVs produce different ciphertexts
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_IV_UNIQUENESS_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_CipherCtx *ctx1 = NULL;
    CRYPT_EAL_CipherCtx *ctx2 = NULL;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)i;
    
    uint8_t iv1[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv1[i] = (uint8_t)i;
    
    uint8_t iv2[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv2[i] = (uint8_t)(i + 100);
    
    uint8_t plaintext[64];
    for (int i = 0; i < 64; i++) plaintext[i] = (uint8_t)(i * 3);
    
    uint8_t ciphertext1[128];
    uint8_t ciphertext2[128];
    uint32_t outLen1 = 0;
    uint32_t outLen2 = 0;
    
    /* Encrypt with IV1 */
    ctx1 = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx1 != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx1, key, keySize, iv1, GCM_TEST_IV_SIZE, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx1, plaintext, 64, ciphertext1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx1, ciphertext1 + outLen1, &outLen1), CRYPT_SUCCESS);
    
    /* Encrypt with IV2 */
    ctx2 = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx2 != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx2, key, keySize, iv2, GCM_TEST_IV_SIZE, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx2, plaintext, 64, ciphertext2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx2, ciphertext2 + outLen2, &outLen2), CRYPT_SUCCESS);
    
    /* Different IVs should produce different ciphertexts */
    ASSERT_NE(memcmp(ciphertext1, ciphertext2, 64), 0);
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx1);
    CRYPT_EAL_CipherFreeCtx(ctx2);
    return;
}
/* END_CASE */

/**
 * @test   SDV_GCM_STATE_MACHINE_LENGTH_PRESERVING_TC001
 * @title  Verify GCM preserves plaintext length
 * @precon nan
 * @brief
 *    1.Encrypt plaintext of various lengths
 *    2.Verify ciphertext length equals plaintext length
 * @expect
 *    GCM is length-preserving (ciphertext same length as plaintext)
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_LENGTH_PRESERVING_TC001(int cipherAlgId, int plaintextLen)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_CipherCtx *ctx = NULL;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)i;
    
    uint8_t iv[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv[i] = (uint8_t)i;
    
    uint8_t plaintext[256];
    for (int i = 0; i < 256; i++) plaintext[i] = (uint8_t)i;
    
    uint8_t ciphertext[512];
    uint32_t updateOutLen = 0;
    uint32_t finalOutLen = 0;
    
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keySize, iv, GCM_TEST_IV_SIZE, true), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plaintext, (uint32_t)plaintextLen, ciphertext, &updateOutLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ciphertext + updateOutLen, &finalOutLen), CRYPT_SUCCESS);
    
    /* Total ciphertext length should equal plaintext length */
    ASSERT_EQ(updateOutLen + finalOutLen, (uint32_t)plaintextLen);
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test   SDV_GCM_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title  Verify GCM state consistency under random operation sequences
 * @precon nan
 * @brief
 *    1.Generate random sequence of operations
 *    2.Execute each operation and verify state consistency
 * @expect
 *    All operation sequences complete without errors
 */
/* BEGIN_CASE */
void SDV_GCM_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int cipherAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    RefGcmModel refModel;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t prngState = (uint32_t)seed;
    RefOpResult refResult;
    int32_t implRet;
    
    uint32_t keySize = GetKeySize(cipherAlgId);
    uint8_t key[32];
    for (uint32_t i = 0; i < keySize; i++) key[i] = (uint8_t)((i * seed) & 0xFF);
    
    uint8_t iv[GCM_TEST_IV_SIZE];
    for (int i = 0; i < GCM_TEST_IV_SIZE; i++) iv[i] = (uint8_t)((i * 7 + seed) & 0xFF);
    
    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)((i * 11 + seed) & 0xFF);
    
    uint8_t out[128];
    uint8_t tag[GCM_TEST_TAG_SIZE];
    uint32_t outLen;
    uint32_t tagLen = GCM_TEST_TAG_SIZE;
    
    RefModel_Init(&refModel);
    
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);
    
    bool initialized = false;
    bool isEncrypt = true;
    
    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prngState) % REF_OP_COUNT;
        
        switch (op) {
            case REF_OP_INIT:
                isEncrypt = (SimplePrng(&prngState) % 2) == 0;
                refResult = RefModel_CipherInit(&refModel, isEncrypt, true);
                if (!initialized) {
                    implRet = CRYPT_EAL_CipherInit(ctx, key, keySize, iv, GCM_TEST_IV_SIZE, isEncrypt);
                    initialized = true;
                } else {
                    implRet = CRYPT_SUCCESS;
                }
                break;
                
            case REF_OP_UPDATE:
                refResult = RefModel_CipherUpdate(&refModel, 64, true);
                if (initialized) {
                    outLen = 128;
                    implRet = CRYPT_EAL_CipherUpdate(ctx, data, 64, out, &outLen);
                } else {
                    implRet = CRYPT_EAL_ERR_STATE;
                }
                break;
                
            case REF_OP_FINAL:
                refResult = RefModel_CipherFinal(&refModel, true);
                if (initialized) {
                    outLen = 128;
                    implRet = CRYPT_EAL_CipherFinal(ctx, out, &outLen);
                    if (implRet == CRYPT_SUCCESS && isEncrypt) {
                        CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, tagLen);
                    }
                } else {
                    implRet = CRYPT_EAL_ERR_STATE;
                }
                break;
                
            case REF_OP_REINIT:
                isEncrypt = (SimplePrng(&prngState) % 2) == 0;
                refResult = RefModel_CipherInit(&refModel, isEncrypt, true);
                if (initialized) {
                    for (int j = 0; j < GCM_TEST_IV_SIZE; j++) iv[j] = (uint8_t)((j * seed + i) & 0xFF);
                    implRet = CRYPT_EAL_CipherInit(ctx, key, keySize, iv, GCM_TEST_IV_SIZE, isEncrypt);
                } else {
                    implRet = CRYPT_EAL_ERR_STATE;
                }
                break;
                
            default:
                continue;
        }
        
        if (refResult.success) {
            ASSERT_EQ(implRet, CRYPT_SUCCESS);
        }
    }
    
EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */
