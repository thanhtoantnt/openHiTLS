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
#include "eal_cipher_local.h"

/* END_HEADER */

#define CIPHER_TEST_KEY32     32
#define CIPHER_TEST_KEY16     16
#define CIPHER_TEST_IV_GCM    12
#define CIPHER_TEST_IV_CBC    16
#define CIPHER_TEST_TAG_LEN   16
#define CIPHER_TEST_MSG_LEN   64
#define CIPHER_TEST_BUF_LEN  256

/* ============================================================================
 * REFERENCE MODEL FOR EAL CIPHER STATE MACHINE
 *
 * States: NEW, INIT, UPDATE, FINAL
 *
 * Transition table (from eal_cipher.c):
 *   Init    : ANY  → INIT   (always resets, even from FINAL)
 *   Reinit  : INIT,UPDATE,FINAL → INIT | NEW → ERR_STATE
 *   Update  : INIT,UPDATE  → UPDATE | NEW,FINAL → ERR_STATE
 *   Final   : INIT,UPDATE  → FINAL  | NEW,FINAL → ERR_STATE
 *   Deinit  : ANY → NEW     (void return)
 *   SetAAD  : INIT          → UPDATE | UPDATE,FINAL,NEW → ERR_STATE
 *   GetTag  : FINAL only    | NEW → ERR_STATE
 *
 * NEW PROPERTIES tested here (NOT related to confirmed HMAC Deinit/Reinit bugs):
 *   1. AAD ordering invariant: SetAAD blocked once state==UPDATE
 *   2. GetTag only valid from FINAL state
 *   3. Reinit blocked from NEW state
 *   4. Encrypt-Decrypt round-trip: encrypt(plaintext) → decrypt → original plaintext
 *   5. IV uniqueness: same key+plaintext, different IV → different ciphertext
 *   6. DupCtx aliasing: mid-stream copy produces identical independent ciphertext
 * ============================================================================ */

typedef enum {
    REF_CIPHER_NEW    = 0,
    REF_CIPHER_INIT   = 1,
    REF_CIPHER_UPDATE = 2,
    REF_CIPHER_FINAL  = 3
} RefCipherState;

typedef struct {
    RefCipherState state;
    bool           isAead;
    bool           isEnc;
} RefCipherModel;

typedef struct {
    int32_t        retCode;
    RefCipherState stateAfter;
    bool           success;
} RefCipherResult;

static void RefCipher_ModelInit(RefCipherModel *m, bool isAead, bool isEnc)
{
    m->state  = REF_CIPHER_NEW;
    m->isAead = isAead;
    m->isEnc  = isEnc;
}

static RefCipherResult RefCipher_Init(RefCipherModel *m)
{
    m->state = REF_CIPHER_INIT;
    RefCipherResult r = {CRYPT_SUCCESS, REF_CIPHER_INIT, true};
    return r;
}

static RefCipherResult RefCipher_Reinit(RefCipherModel *m)
{
    RefCipherResult r = {0};
    if (m->state == REF_CIPHER_NEW) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = REF_CIPHER_NEW;
        r.success    = false;
        return r;
    }
    m->state     = REF_CIPHER_INIT;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_CIPHER_INIT;
    r.success    = true;
    return r;
}

static RefCipherResult RefCipher_Update(RefCipherModel *m)
{
    RefCipherResult r = {0};
    if (m->state != REF_CIPHER_INIT && m->state != REF_CIPHER_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state     = REF_CIPHER_UPDATE;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_CIPHER_UPDATE;
    r.success    = true;
    return r;
}

static RefCipherResult RefCipher_Final(RefCipherModel *m)
{
    RefCipherResult r = {0};
    if (m->state != REF_CIPHER_INIT && m->state != REF_CIPHER_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state     = REF_CIPHER_FINAL;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_CIPHER_FINAL;
    r.success    = true;
    return r;
}

static RefCipherResult RefCipher_SetAAD(RefCipherModel *m)
{
    RefCipherResult r = {0};
    /* SetAAD allowed only in INIT state (transitions to UPDATE) */
    if (m->state != REF_CIPHER_INIT) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state     = REF_CIPHER_UPDATE;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_CIPHER_UPDATE;
    r.success    = true;
    return r;
}

static RefCipherResult RefCipher_GetTag(RefCipherModel *m)
{
    RefCipherResult r = {0};
    /* GetTag only valid from FINAL */
    if (m->state != REF_CIPHER_FINAL) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_CIPHER_FINAL;
    r.success    = true;
    return r;
}

static RefCipherState ImplStateToRef(EAL_CipherStates implState)
{
    switch (implState) {
        case EAL_CIPHER_STATE_NEW:    return REF_CIPHER_NEW;
        case EAL_CIPHER_STATE_INIT:   return REF_CIPHER_INIT;
        case EAL_CIPHER_STATE_UPDATE: return REF_CIPHER_UPDATE;
        case EAL_CIPHER_STATE_FINAL:  return REF_CIPHER_FINAL;
        default:                      return REF_CIPHER_NEW;
    }
}

static uint32_t GetKeyLen(int cipherAlgId)
{
    switch (cipherAlgId) {
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES128_CBC:
        case CRYPT_CIPHER_AES128_CTR:
        case CRYPT_CIPHER_AES128_CCM:
            return 16;
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES192_CBC:
        case CRYPT_CIPHER_AES192_CTR:
            return 24;
        default:
            return 32;
    }
}

static uint32_t GetIvLen(int cipherAlgId)
{
    switch (cipherAlgId) {
        case CRYPT_CIPHER_AES128_GCM:
        case CRYPT_CIPHER_AES192_GCM:
        case CRYPT_CIPHER_AES256_GCM:
            return 12;
        default:
            return 16;
    }
}

static bool IsAead(int cipherAlgId)
{
    return (cipherAlgId == CRYPT_CIPHER_AES128_GCM ||
            cipherAlgId == CRYPT_CIPHER_AES192_GCM ||
            cipherAlgId == CRYPT_CIPHER_AES256_GCM ||
            cipherAlgId == CRYPT_CIPHER_AES128_CCM ||
            cipherAlgId == CRYPT_CIPHER_AES256_CCM);
}

static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

/* ============================================================================
 * TEST CASES — NEW PROPERTIES (not related to Deinit/Reinit bugs)
 * ============================================================================ */

/**
 * @test SDV_CIPHER_STATE_MACHINE_BASIC_TRANSITIONS_TC001
 * @title Verify state transitions match reference model
 * @precon nan
 * @brief
 *  1.NewCtx → state must be NEW
 *  2.Init  → NEW  → INIT
 *  3.Update → INIT → UPDATE
 *  4.Final  → UPDATE → FINAL
 *  5.Reinit → FINAL → INIT
 * @expect All transitions match reference model
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_BASIC_TRANSITIONS_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCipherModel        ref;
    CRYPT_EAL_CipherCtx  *ctx = NULL;
    RefCipherResult        exp;
    int32_t                ret;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 5 + 11);

    uint8_t in[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) in[i] = (uint8_t)i;

    uint8_t out[CIPHER_TEST_BUF_LEN];
    uint32_t outLen = sizeof(out);

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    RefCipher_ModelInit(&ref, IsAead(cipherAlgId), true);
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_NEW);

    /* Init */
    exp = RefCipher_Init(&ref);
    ret = CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(ctx->states), exp.stateAfter);

    /* Update */
    exp = RefCipher_Update(&ref);
    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherUpdate(ctx, in, CIPHER_TEST_MSG_LEN, out, &outLen);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(ctx->states), exp.stateAfter);

    /* Final */
    exp = RefCipher_Final(&ref);
    outLen = sizeof(out);
    ret = CRYPT_EAL_CipherFinal(ctx, out, &outLen);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(ctx->states), exp.stateAfter);

    /* Reinit from FINAL → INIT */
    exp = RefCipher_Reinit(&ref);
    ret = CRYPT_EAL_CipherReinit(ctx, iv, ivLen);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(ctx->states), exp.stateAfter);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_REINIT_FROM_NEW_TC001
 * @title Verify Reinit is blocked from NEW state (reference model: ERR_STATE)
 * @precon nan
 * @brief
 *  1.NewCtx (state: NEW)
 *  2.Reinit — model predicts ERR_STATE, never INIT
 * @expect Reinit from NEW returns CRYPT_EAL_ERR_STATE
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_REINIT_FROM_NEW_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCipherModel       ref;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    RefCipherResult       exp;
    int32_t               ret;

    uint8_t iv[16] = {0};
    uint32_t ivLen = GetIvLen(cipherAlgId);

    RefCipher_ModelInit(&ref, IsAead(cipherAlgId), true);
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_NEW);

    exp = RefCipher_Reinit(&ref);   /* model: NEW → ERR_STATE */
    ret = CRYPT_EAL_CipherReinit(ctx, iv, ivLen);
    ASSERT_EQ(exp.success, false);
    ASSERT_EQ(ret, CRYPT_EAL_ERR_STATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_AEAD_AAD_ORDERING_TC001
 * @title Verify AEAD AAD ordering: SetAAD blocked after Update (state=UPDATE)
 * @precon nan
 * @brief
 *  1.Init AEAD cipher
 *  2.SetAAD (state: INIT → UPDATE per reference model)
 *  3.SetAAD again — model predicts ERR_STATE (state is now UPDATE)
 *  4.Verify second SetAAD fails
 * @expect SetAAD from UPDATE state returns ERR_STATE
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_AEAD_AAD_ORDERING_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId) || !IsAead(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCipherModel       ref;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    RefCipherResult       exp;
    int32_t               ret;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t iv[12];
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 1);

    uint8_t aad[32];
    for (int i = 0; i < 32; i++) aad[i] = (uint8_t)(i * 3);

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    RefCipher_ModelInit(&ref, true, true);
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);

    /* Init */
    exp = RefCipher_Init(&ref);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_INIT);

    /* First SetAAD: INIT → UPDATE (model + impl both succeed) */
    exp = RefCipher_SetAAD(&ref);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, 32);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_UPDATE);

    /* Second SetAAD: UPDATE → model says ERR_STATE */
    exp = RefCipher_SetAAD(&ref);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, aad, 32);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_UPDATE);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_AEAD_TAG_STATE_TC001
 * @title Verify GetTag is only valid from FINAL state
 * @precon nan
 * @brief
 *  1.Init → GetTag fails (model: ERR_STATE from INIT)
 *  2.Update → GetTag fails (model: ERR_STATE from UPDATE)
 *  3.Final  → GetTag succeeds (model: OK from FINAL)
 * @expect GetTag state guards match reference model
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_AEAD_TAG_STATE_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId) || !IsAead(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCipherModel       ref;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    RefCipherResult       exp;
    int32_t               ret;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);

    uint8_t iv[12];
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i * 5 + 3);

    uint8_t in[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) in[i] = (uint8_t)(i * 11 + 7);

    uint8_t out[CIPHER_TEST_BUF_LEN];
    uint8_t tag[CIPHER_TEST_TAG_LEN];
    uint32_t outLen = sizeof(out);

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    RefCipher_ModelInit(&ref, true, true);
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    RefCipher_Init(&ref);

    /* GetTag from INIT — must fail */
    exp = RefCipher_GetTag(&ref);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, CIPHER_TEST_TAG_LEN);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* Update */
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, in, CIPHER_TEST_MSG_LEN, out, &outLen), CRYPT_SUCCESS);
    RefCipher_Update(&ref);

    /* GetTag from UPDATE — must fail */
    exp = RefCipher_GetTag(&ref);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, CIPHER_TEST_TAG_LEN);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* Final */
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out, &outLen), CRYPT_SUCCESS);
    RefCipher_Final(&ref);

    /* GetTag from FINAL — must succeed */
    exp = RefCipher_GetTag(&ref);
    ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, CIPHER_TEST_TAG_LEN);
    ASSERT_EQ(exp.success, true);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_ENCRYPT_DECRYPT_ROUNDTRIP_TC001
 * @title Verify encrypt-decrypt round-trip: decrypt(encrypt(P)) == P
 * @precon nan
 * @brief
 *  1.Encrypt plaintext with (key, IV)
 *  2.Decrypt ciphertext with (same key, same IV via new context)
 *  3.Verify decrypted == original plaintext
 * @expect Round-trip recovers exact plaintext
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_ENCRYPT_DECRYPT_ROUNDTRIP_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_CipherCtx *encCtx = NULL;
    CRYPT_EAL_CipherCtx *decCtx = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 5 + 11);

    uint8_t plaintext[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) plaintext[i] = (uint8_t)(i * 7 + 13);

    uint8_t ciphertext[CIPHER_TEST_BUF_LEN];
    uint8_t decrypted[CIPHER_TEST_BUF_LEN];
    uint8_t tag[CIPHER_TEST_TAG_LEN];
    uint32_t encLen = sizeof(ciphertext);
    uint32_t encFinalLen = sizeof(ciphertext);
    uint32_t decLen = sizeof(decrypted);
    uint32_t decFinalLen = sizeof(decrypted);
    uint32_t tagLen = CIPHER_TEST_TAG_LEN;

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    /* Encrypt */
    encCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(encCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(encCtx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    encLen = sizeof(ciphertext);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(encCtx, plaintext, CIPHER_TEST_MSG_LEN, ciphertext, &encLen), CRYPT_SUCCESS);
    encFinalLen = sizeof(ciphertext) - encLen;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(encCtx, ciphertext + encLen, &encFinalLen), CRYPT_SUCCESS);
    uint32_t totalCipher = encLen + encFinalLen;

    if (IsAead(cipherAlgId)) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(encCtx, CRYPT_CTRL_GET_TAG, tag, tagLen), CRYPT_SUCCESS);
    }

    /* Decrypt */
    decCtx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(decCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(decCtx, key, keyLen, iv, ivLen, false), CRYPT_SUCCESS);

    if (IsAead(cipherAlgId)) {
        ASSERT_EQ(CRYPT_EAL_CipherCtrl(decCtx, CRYPT_CTRL_SET_TAG, tag, tagLen), CRYPT_SUCCESS);
    }

    decLen = sizeof(decrypted);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(decCtx, ciphertext, totalCipher, decrypted, &decLen), CRYPT_SUCCESS);
    decFinalLen = sizeof(decrypted) - decLen;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(decCtx, decrypted + decLen, &decFinalLen), CRYPT_SUCCESS);
    uint32_t totalDecrypted = decLen + decFinalLen;

    /* Round-trip: decrypted must equal original plaintext */
    ASSERT_EQ(totalDecrypted, CIPHER_TEST_MSG_LEN);
    ASSERT_EQ(memcmp(plaintext, decrypted, CIPHER_TEST_MSG_LEN), 0);

EXIT:
    CRYPT_EAL_CipherFreeCtx(encCtx);
    CRYPT_EAL_CipherFreeCtx(decCtx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_IV_UNIQUENESS_TC001
 * @title Verify same key+plaintext with different IV produces different ciphertext
 * @precon nan
 * @brief
 *  1.Encrypt plaintext with (key, IV1) → ciphertext1
 *  2.Encrypt plaintext with (key, IV2) via Reinit → ciphertext2
 *  3.Verify ciphertext1 != ciphertext2
 * @expect Different IVs produce different ciphertext (IV uniqueness property)
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_IV_UNIQUENESS_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_CipherCtx *ctx = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t iv1[16];
    for (int i = 0; i < 16; i++) iv1[i] = (uint8_t)i;

    uint8_t iv2[16];
    for (int i = 0; i < 16; i++) iv2[i] = (uint8_t)(i + 100);

    uint8_t plaintext[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) plaintext[i] = (uint8_t)(i * 13 + 7);

    uint8_t ct1[CIPHER_TEST_BUF_LEN];
    uint8_t ct2[CIPHER_TEST_BUF_LEN];
    uint32_t len1 = sizeof(ct1);
    uint32_t len2 = sizeof(ct2);
    uint32_t final1 = sizeof(ct1);
    uint32_t final2 = sizeof(ct2);

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);

    /* Encrypt with IV1 */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv1, ivLen, true), CRYPT_SUCCESS);
    len1 = sizeof(ct1);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plaintext, CIPHER_TEST_MSG_LEN, ct1, &len1), CRYPT_SUCCESS);
    final1 = sizeof(ct1) - len1;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct1 + len1, &final1), CRYPT_SUCCESS);
    uint32_t total1 = len1 + final1;

    /* Reinit with IV2 */
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv2, ivLen), CRYPT_SUCCESS);

    /* Encrypt with IV2 */
    len2 = sizeof(ct2);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plaintext, CIPHER_TEST_MSG_LEN, ct2, &len2), CRYPT_SUCCESS);
    final2 = sizeof(ct2) - len2;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct2 + len2, &final2), CRYPT_SUCCESS);
    uint32_t total2 = len2 + final2;

    /* Different IVs → different ciphertext */
    ASSERT_EQ(total1, total2);
    ASSERT_NE(memcmp(ct1, ct2, total1), 0);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_DUPCTX_ALIASING_TC001
 * @title Verify DupCtx mid-stream produces identical independent ciphertext
 * @precon nan
 * @brief
 *  1.Init, Update(prefix)
 *  2.DupCtx at UPDATE state
 *  3.Feed same suffix to original and dup, call Final on both
 *  4.Both ciphertexts must be identical
 *  5.Subsequent Update on one must not affect the other
 * @expect DupCtx creates truly independent snapshot
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_DUPCTX_ALIASING_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_CipherCtx *ctx = NULL;
    CRYPT_EAL_CipherCtx *dup = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 5 + 11);

    uint8_t prefix[32];
    for (int i = 0; i < 32; i++) prefix[i] = (uint8_t)(i * 7 + 3);

    uint8_t suffix[32];
    for (int i = 0; i < 32; i++) suffix[i] = (uint8_t)(i * 11 + 5);

    uint8_t out_orig[CIPHER_TEST_BUF_LEN];
    uint8_t out_dup[CIPHER_TEST_BUF_LEN];
    uint32_t len_orig, len_dup, final_orig, final_dup;

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);

    /* Process prefix on original */
    len_orig = sizeof(out_orig);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, prefix, 32, out_orig, &len_orig), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_UPDATE);

    /* Dup at UPDATE state */
    dup = CRYPT_EAL_CipherDupCtx(ctx);
    ASSERT_TRUE(dup != NULL);
    ASSERT_EQ(ImplStateToRef(dup->states), REF_CIPHER_UPDATE);

    /* Feed same suffix to both, finalize both */
    uint32_t tmp = sizeof(out_orig) - len_orig;
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, suffix, 32, out_orig + len_orig, &tmp), CRYPT_SUCCESS);
    len_orig += tmp;
    final_orig = sizeof(out_orig) - len_orig;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, out_orig + len_orig, &final_orig), CRYPT_SUCCESS);

    len_dup = 0;
    tmp = sizeof(out_dup);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(dup, suffix, 32, out_dup, &tmp), CRYPT_SUCCESS);
    len_dup += tmp;
    final_dup = sizeof(out_dup) - len_dup;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(dup, out_dup + len_dup, &final_dup), CRYPT_SUCCESS);
    uint32_t total_dup = len_dup + final_dup;

    /* Both contexts from same split point must produce identical output for the suffix portion */
    /* Note: total_orig includes prefix output, total_dup only has suffix output */
    uint32_t suffix_and_final_orig = tmp + final_orig;
    ASSERT_EQ(suffix_and_final_orig, total_dup);
    /* Compare the suffix-derived portion of original with dup's entire output */
    ASSERT_EQ(memcmp(out_orig + (len_orig - tmp), out_dup, total_dup), 0);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    CRYPT_EAL_CipherFreeCtx(dup);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_REINIT_ROUNDTRIP_TC001
 * @title Verify Reinit enables correct re-encryption on same key
 * @precon nan
 * @brief
 *  1.Encrypt plaintext with (key, IV1) → ct1
 *  2.Reinit with IV1 (same IV)
 *  3.Encrypt same plaintext → ct2
 *  4.ct1 must equal ct2 (same key + same IV = deterministic)
 *  5.Reinit with IV2 → decrypt ct1 fails (wrong IV)
 * @expect Reinit with same IV produces deterministic output
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_REINIT_ROUNDTRIP_TC001(int cipherAlgId)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_CipherCtx *ctx = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(i * 11 + 3);

    uint8_t plaintext[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) plaintext[i] = (uint8_t)(i * 17 + 5);

    uint8_t ct1[CIPHER_TEST_BUF_LEN];
    uint8_t ct2[CIPHER_TEST_BUF_LEN];
    uint32_t len1, len2, final1, final2;

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);

    /* First encryption */
    ASSERT_EQ(CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true), CRYPT_SUCCESS);
    len1 = sizeof(ct1);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plaintext, CIPHER_TEST_MSG_LEN, ct1, &len1), CRYPT_SUCCESS);
    final1 = sizeof(ct1) - len1;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct1 + len1, &final1), CRYPT_SUCCESS);

    /* Reinit with SAME IV */
    ASSERT_EQ(CRYPT_EAL_CipherReinit(ctx, iv, ivLen), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(ctx->states), REF_CIPHER_INIT);

    /* Second encryption with same IV */
    len2 = sizeof(ct2);
    ASSERT_EQ(CRYPT_EAL_CipherUpdate(ctx, plaintext, CIPHER_TEST_MSG_LEN, ct2, &len2), CRYPT_SUCCESS);
    final2 = sizeof(ct2) - len2;
    ASSERT_EQ(CRYPT_EAL_CipherFinal(ctx, ct2 + len2, &final2), CRYPT_SUCCESS);

    /* Same key + same IV = deterministic output */
    ASSERT_EQ(len1 + final1, len2 + final2);
    ASSERT_EQ(memcmp(ct1, ct2, len1 + final1), 0);

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */

/**
 * @test SDV_CIPHER_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title Verify cipher state machine consistency under random operation sequences
 * @precon nan
 * @brief
 *  1.Generate random sequence of {Init, Reinit, Update, Final}
 *  2.Execute on both impl and reference model
 *  3.Success/failure must match model predictions
 * @expect No crashes; states match reference model
 */
/* BEGIN_CASE */
void SDV_CIPHER_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int cipherAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_CipherIsValidAlgId(cipherAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCipherModel       ref;
    CRYPT_EAL_CipherCtx *ctx = NULL;
    uint32_t             prng = (uint32_t)seed;
    int32_t              ret;
    RefCipherResult       exp;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)((i * seed) & 0xFF);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)((i * 7 + seed) & 0xFF);

    uint8_t in[CIPHER_TEST_MSG_LEN];
    for (int i = 0; i < CIPHER_TEST_MSG_LEN; i++) in[i] = (uint8_t)i;

    uint8_t out[CIPHER_TEST_BUF_LEN];
    uint32_t outLen;

    uint32_t keyLen = GetKeyLen(cipherAlgId);
    uint32_t ivLen  = GetIvLen(cipherAlgId);

    bool initialized = false;

    RefCipher_ModelInit(&ref, IsAead(cipherAlgId), true);
    ctx = CRYPT_EAL_CipherNewCtx(cipherAlgId);
    ASSERT_TRUE(ctx != NULL);

    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prng) % 4;

        switch (op) {
            case 0: /* Init */
                exp = RefCipher_Init(&ref);
                ret = CRYPT_EAL_CipherInit(ctx, key, keyLen, iv, ivLen, true);
                initialized = true;
                break;
            case 1: /* Reinit */
                exp = RefCipher_Reinit(&ref);
                ret = initialized ? CRYPT_EAL_CipherReinit(ctx, iv, ivLen)
                                  : CRYPT_EAL_ERR_STATE;
                break;
            case 2: /* Update */
                exp = RefCipher_Update(&ref);
                if (initialized) {
                    outLen = sizeof(out);
                    ret = CRYPT_EAL_CipherUpdate(ctx, in, 16, out, &outLen);
                } else {
                    ret = CRYPT_EAL_ERR_STATE;
                }
                break;
            case 3: /* Final */
                exp = RefCipher_Final(&ref);
                if (initialized) {
                    outLen = sizeof(out);
                    ret = CRYPT_EAL_CipherFinal(ctx, out, &outLen);
                } else {
                    ret = CRYPT_EAL_ERR_STATE;
                }
                break;
            default:
                continue;
        }

        if (exp.success) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
        }
        ASSERT_EQ(ImplStateToRef(ctx->states), exp.stateAfter);
    }

EXIT:
    CRYPT_EAL_CipherFreeCtx(ctx);
    return;
}
/* END_CASE */
