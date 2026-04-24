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
#include "crypt_eal_mac.h"

/* END_HEADER */

#define CMAC_TEST_MAX_KEY_SIZE  32
#define CMAC_TEST_MAX_MSG_SIZE 128
#define CMAC_TEST_MAX_OUT_SIZE  16
#define CMAC_TEST_MAX_OPS      100

/* ============================================================================
 * REFERENCE MODEL FOR CMAC INTERNAL STATE MACHINE
 *
 * CMAC uses the same lifecycle as HMAC: Init / Update / Final / Reinit / Deinit
 * The internal CipherMacReinit and CipherMacDeinit live in cipher_mac_common.c.
 *
 * From source inspection:
 *   CipherMacReinit: only checks ctx != NULL — no state validation → same as HMAC BUG-2
 *   CipherMacDeinit: cleanses ctx->key bytes but does NOT null ctx->key pointer
 *                    → same class of bug as HMAC BUG-1
 *
 * Reference model transition table:
 *   Init   : NEW, FINAL → INIT       | INIT, UPDATE → ERR (already init'd without Final)
 *   Update : INIT, UPDATE → UPDATE   | otherwise → ERR_STATE
 *   Final  : INIT, UPDATE → FINAL    | otherwise → ERR_STATE
 *   Reinit : UPDATE, FINAL → INIT    | otherwise → ERR_STATE
 *   Deinit : ANY → DEINIT (zeroed)
 *
 * ============================================================================ */

typedef CRYPT_EAL_MacCtx CRYPT_CMAC_Ctx;
#define CRYPT_CMAC_NewCtx(id)           CRYPT_EAL_MacNewCtx(id)
#define CRYPT_CMAC_Init(ctx, key, len)  CRYPT_EAL_MacInit(ctx, key, len)
#define CRYPT_CMAC_Update(ctx, in, len) CRYPT_EAL_MacUpdate(ctx, in, len)
#define CRYPT_CMAC_Final(ctx, out, len) CRYPT_EAL_MacFinal(ctx, out, len)
#define CRYPT_CMAC_Reinit(ctx)          CRYPT_EAL_MacReinit(ctx)
#define CRYPT_CMAC_Deinit(ctx)          (CRYPT_EAL_MacDeinit(ctx), CRYPT_SUCCESS)
#define CRYPT_CMAC_FreeCtx(ctx)         CRYPT_EAL_MacFreeCtx(ctx)
#define CRYPT_CMAC_DupCtx(ctx)          CRYPT_EAL_MacDupCtx(ctx)

typedef enum {
    REF_CMAC_NEW    = 0,
    REF_CMAC_INIT   = 1,
    REF_CMAC_UPDATE = 2,
    REF_CMAC_FINAL  = 3,
    REF_CMAC_DEINIT = 4
} RefCmacState;

typedef struct {
    RefCmacState state;
    uint32_t     updateCount;
} RefCmacModel;

typedef struct {
    int32_t      retCode;
    RefCmacState stateAfter;
    bool         success;
} RefCmacResult;

static void RefCmac_ModelInit(RefCmacModel *m)
{
    m->state       = REF_CMAC_NEW;
    m->updateCount = 0;
}

static RefCmacResult RefCmac_Init(RefCmacModel *m, bool willSucceed)
{
    RefCmacResult r = {0};
    if (willSucceed) {
        m->state       = REF_CMAC_INIT;
        m->updateCount = 0;
        r.retCode      = CRYPT_SUCCESS;
        r.success      = true;
    } else {
        r.retCode = CRYPT_NULL_INPUT;
        r.success = false;
    }
    r.stateAfter = m->state;
    return r;
}

static RefCmacResult RefCmac_Update(RefCmacModel *m, uint32_t len, bool willSucceed)
{
    RefCmacResult r = {0};
    if (m->state != REF_CMAC_INIT && m->state != REF_CMAC_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    if (willSucceed) {
        m->state = REF_CMAC_UPDATE;
        m->updateCount++;
        (void)len;
        r.retCode = CRYPT_SUCCESS;
        r.success = true;
    } else {
        r.retCode = CRYPT_NULL_INPUT;
        r.success = false;
    }
    r.stateAfter = m->state;
    return r;
}

static RefCmacResult RefCmac_Final(RefCmacModel *m, bool willSucceed)
{
    RefCmacResult r = {0};
    if (m->state != REF_CMAC_INIT && m->state != REF_CMAC_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    if (willSucceed) {
        m->state  = REF_CMAC_FINAL;
        r.retCode = CRYPT_SUCCESS;
        r.success = true;
    } else {
        r.retCode = CRYPT_NULL_INPUT;
        r.success = false;
    }
    r.stateAfter = m->state;
    return r;
}

/* Reinit: valid from UPDATE or FINAL only */
static RefCmacResult RefCmac_Reinit(RefCmacModel *m)
{
    RefCmacResult r = {0};
    if (m->state != REF_CMAC_UPDATE && m->state != REF_CMAC_FINAL) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state       = REF_CMAC_INIT;
    m->updateCount = 0;
    r.retCode      = CRYPT_SUCCESS;
    r.stateAfter   = REF_CMAC_INIT;
    r.success      = true;
    return r;
}

static RefCmacResult RefCmac_Deinit(RefCmacModel *m)
{
    m->state       = REF_CMAC_DEINIT;
    m->updateCount = 0;
    RefCmacResult r = {CRYPT_SUCCESS, REF_CMAC_DEINIT, true};
    return r;
}

static uint32_t GetCmacKeyLen(int macAlgId)
{
    /* AES-256 requires 32-byte key; AES-128/192 use 16-byte key */
    if (macAlgId == CRYPT_MAC_CMAC_AES256) return 32;
    if (macAlgId == CRYPT_MAC_CMAC_AES192) return 24;
    return 16;
}

/* Simple PRNG */
static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_CMAC_STATE_MACHINE_BASIC_TC001
 * @title Verify CMAC basic state transitions match reference model
 * @precon nan
 * @brief
 *  1.NewCtx
 *  2.Init(key)   → INIT
 *  3.Update(msg) → UPDATE
 *  4.Final       → FINAL
 *  5.Reinit      → INIT
 *  6.Update(msg) + Final → new output
 *  7.Deinit
 * @expect All transitions match reference model
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_BASIC_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCmacModel     ref;
    CRYPT_CMAC_Ctx  *mac = NULL;
    RefCmacResult    exp;
    int32_t          ret;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    uint32_t keyLen = GetCmacKeyLen(macAlgId);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 2);

    uint8_t out[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefCmac_ModelInit(&ref);
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    /* Init */
    exp = RefCmac_Init(&ref, true);
    ret = CRYPT_CMAC_Init(mac, key, keyLen);
    ASSERT_EQ(ret, exp.retCode);

    /* Update */
    exp = RefCmac_Update(&ref, 64, true);
    ret = CRYPT_CMAC_Update(mac, msg, 64);
    ASSERT_EQ(ret, exp.retCode);

    /* Final */
    exp = RefCmac_Final(&ref, true);
    ret = CRYPT_CMAC_Final(mac, out, &outLen);
    ASSERT_EQ(ret, exp.retCode);

    /* Reinit → should succeed from FINAL */
    exp = RefCmac_Reinit(&ref);
    ret = CRYPT_CMAC_Reinit(mac);
    ASSERT_EQ(ret, exp.retCode);

    /* Verify Reinit resets state: Update+Final should work again */
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_CMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac, out, &outLen), CRYPT_SUCCESS);

    /* Deinit */
    exp = RefCmac_Deinit(&ref);
    ret = CRYPT_CMAC_Deinit(mac);

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_DETERMINISM_TC001
 * @title Verify CMAC is deterministic: same key+msg always gives same tag
 * @precon nan
 * @brief
 *  1.Compute CMAC twice with identical key and message
 *  2.Outputs must be equal
 * @expect CMAC(K, m) is deterministic
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_DETERMINISM_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac1 = NULL;
    CRYPT_CMAC_Ctx *mac2 = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 5 + 11);

    uint8_t out1[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out2[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t len1 = sizeof(out1), len2 = sizeof(out2);

    mac1 = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac1, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac1, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac1, out1, &len1), CRYPT_SUCCESS);

    mac2 = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac2, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac2, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac2, out2, &len2), CRYPT_SUCCESS);

    ASSERT_EQ(len1, len2);
    ASSERT_EQ(memcmp(out1, out2, len1), 0);

EXIT:
    CRYPT_CMAC_FreeCtx(mac1);
    CRYPT_CMAC_FreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_CHAINING_TC001
 * @title Verify Update chaining property: split message produces same tag
 * @precon nan
 * @brief
 *  1.CMAC with single Update(full_msg)
 *  2.CMAC with Update(part1) + Update(part2)
 *  3.Outputs must be equal
 * @expect CMAC(K, m1||m2) == CMAC after Update(m1), Update(m2)
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_CHAINING_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac1 = NULL;
    CRYPT_CMAC_Ctx *mac2 = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 11 + 17);

    uint8_t out1[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out2[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t len1 = sizeof(out1), len2 = sizeof(out2);

    mac1 = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac1, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac1, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac1, out1, &len1), CRYPT_SUCCESS);

    mac2 = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac2, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac2, msg,      32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac2, msg + 32, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac2, out2, &len2), CRYPT_SUCCESS);

    ASSERT_EQ(len1, len2);
    ASSERT_EQ(memcmp(out1, out2, len1), 0);

EXIT:
    CRYPT_CMAC_FreeCtx(mac1);
    CRYPT_CMAC_FreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_REINIT_RESETS_TC001
 * @title Verify Reinit produces same result as fresh Init with same key
 * @precon nan
 * @brief
 *  1.Init(key), Update(msg1), Final → out1
 *  2.Reinit, Update(msg2), Final → out2
 *  3.Fresh: Init(key), Update(msg2), Final → out3
 *  4.out2 == out3
 * @expect Reinit is equivalent to fresh Init with same key
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_REINIT_RESETS_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac1  = NULL;
    CRYPT_CMAC_Ctx *fresh = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 23);

    uint8_t msg1[64];
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64];
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 7 + 13);

    uint8_t out2[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out3[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t len1 = CMAC_TEST_MAX_OUT_SIZE;
    uint32_t len2 = sizeof(out2), len3 = sizeof(out3);

    mac1 = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac1, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac1, msg1, 64), CRYPT_SUCCESS);
    uint8_t out1[CMAC_TEST_MAX_OUT_SIZE];
    ASSERT_EQ(CRYPT_CMAC_Final(mac1, out1, &len1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_CMAC_Reinit(mac1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac1, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac1, out2, &len2), CRYPT_SUCCESS);

    fresh = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(fresh, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(fresh, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(fresh, out3, &len3), CRYPT_SUCCESS);

    ASSERT_EQ(len2, len3);
    ASSERT_EQ(memcmp(out2, out3, len2), 0);

EXIT:
    CRYPT_CMAC_FreeCtx(mac1);
    CRYPT_CMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_REINIT_FROM_NEW_TC001
 * @title Verify Reinit fails from NEW state (reference model: ERR_STATE)
 * @precon nan
 * @brief
 *  1.NewCtx (state: NEW)
 *  2.Reinit — reference model says ERR_STATE
 * @expect Reinit from NEW returns error
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_REINIT_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCmacModel    ref;
    CRYPT_CMAC_Ctx *mac = NULL;
    RefCmacResult   exp;
    int32_t         ret;

    RefCmac_ModelInit(&ref);
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    exp = RefCmac_Reinit(&ref);   /* model: NEW → ERR_STATE */
    ret = CRYPT_CMAC_Reinit(mac);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);  /* implementation should also fail */

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_REINIT_FROM_INIT_TC001
 * @title Verify Reinit fails from INIT state (reference model: ERR_STATE)
 * @precon nan
 * @brief
 *  1.Init(key) (state: INIT)
 *  2.Reinit — reference model says ERR_STATE (no data processed yet)
 * @expect Reinit from INIT returns error
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_REINIT_FROM_INIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCmacModel    ref;
    CRYPT_CMAC_Ctx *mac = NULL;
    RefCmacResult   exp;
    int32_t         ret;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    RefCmac_ModelInit(&ref);
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    RefCmac_Init(&ref, true);
    ASSERT_EQ(CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);

    exp = RefCmac_Reinit(&ref);   /* INIT → ERR_STATE per reference model */
    ret = CRYPT_CMAC_Reinit(mac);
    if (exp.success == false) {
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_DEINIT_THEN_UPDATE_TC001
 * @title Verify Update fails after Deinit — analogue of HMAC BUG-1
 * @precon nan
 * @brief
 *  1.Init, Update, Final, Deinit
 *  2.Update — should fail (context is deinit'd)
 * @expect Update after Deinit returns error (not CRYPT_SUCCESS)
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_DEINIT_THEN_UPDATE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t outLen = sizeof(out);

    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    ASSERT_EQ(CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac, out, &outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_CMAC_Deinit(mac), CRYPT_SUCCESS);

    /* After Deinit, Update must fail — key is zeroed */
    int32_t ret = CRYPT_CMAC_Update(mac, msg, 64);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_DEINIT_THEN_REINIT_TC001
 * @title Verify Reinit+Final after Deinit produces wrong output — analogue of HMAC BUG-1 case B
 * @precon nan
 * @brief
 *  1.Init, Update, Final, Deinit
 *  2.Reinit — may succeed or fail
 *  3.Update, Final — if both succeed, output is wrong (derived from zeroed key)
 *  4.Test expects Final to fail, or output to differ from correct output
 * @expect Reinit or Final fails after Deinit
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_DEINIT_THEN_REINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac   = NULL;
    CRYPT_CMAC_Ctx *fresh = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out_correct[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out_after_deinit[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t len_correct = sizeof(out_correct);
    uint32_t len_deinit  = sizeof(out_after_deinit);

    /* Compute correct output first */
    fresh = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(fresh, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(fresh, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(fresh, out_correct, &len_correct), CRYPT_SUCCESS);

    /* Now test deinit → reinit path */
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(mac, out_after_deinit, &len_deinit), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_CMAC_Deinit(mac), CRYPT_SUCCESS);

    int32_t reinitRet = CRYPT_CMAC_Reinit(mac);
    int32_t updateRet = CRYPT_CMAC_Update(mac, msg, 64);

    if (reinitRet == CRYPT_SUCCESS && updateRet == CRYPT_SUCCESS) {
        len_deinit = sizeof(out_after_deinit);
        int32_t finalRet = CRYPT_CMAC_Final(mac, out_after_deinit, &len_deinit);
        /* Either Final must fail, or output must differ from correct output */
        if (finalRet == CRYPT_SUCCESS) {
            ASSERT_NE(memcmp(out_after_deinit, out_correct, len_correct), 0);
        }
    }

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    CRYPT_CMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_DUP_TC001
 * @title Verify DupCtx produces an independent context with same key
 * @precon nan
 * @brief
 *  1.Init, Update(msg1)
 *  2.DupCtx
 *  3.Original: Final → out1; Dup: Final → out2
 *  4.out1 == out2 (same state at dup)
 *  5.Dup: Reinit, Update(msg2), Final → out3
 *  6.Fresh: Init, Update(msg2), Final → out4
 *  7.out3 == out4 (Reinit on dup is equivalent to fresh Init)
 * @expect DupCtx creates independent copy; Reinit on dup works correctly
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_DUP_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac   = NULL;
    CRYPT_CMAC_Ctx *dup   = NULL;
    CRYPT_CMAC_Ctx *fresh = NULL;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 3);

    uint8_t msg1[64];
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64];
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 13 + 7);

    uint8_t out1[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out2[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out3[CMAC_TEST_MAX_OUT_SIZE];
    uint8_t out4[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t len1 = sizeof(out1), len2 = sizeof(out2);
    uint32_t len3 = sizeof(out3), len4 = sizeof(out4);

    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(mac, msg1, 64), CRYPT_SUCCESS);

    dup = CRYPT_CMAC_DupCtx(mac);
    ASSERT_TRUE(dup != NULL);

    ASSERT_EQ(CRYPT_CMAC_Final(mac, out1, &len1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(dup, out2, &len2), CRYPT_SUCCESS);
    ASSERT_EQ(len1, len2);
    ASSERT_EQ(memcmp(out1, out2, len1), 0);

    ASSERT_EQ(CRYPT_CMAC_Reinit(dup), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(dup, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(dup, out3, &len3), CRYPT_SUCCESS);

    fresh = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(fresh, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Update(fresh, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_CMAC_Final(fresh, out4, &len4), CRYPT_SUCCESS);

    ASSERT_EQ(len3, len4);
    ASSERT_EQ(memcmp(out3, out4, len3), 0);

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    CRYPT_CMAC_FreeCtx(dup);
    CRYPT_CMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title Verify CMAC state consistency under random operation sequences
 * @precon nan
 * @brief
 *  1.Generate random sequence of {Init, Update, Final, Reinit, Deinit}
 *  2.Execute on both impl and reference model
 *  3.Where reference predicts success, impl must succeed
 *  4.No crashes must occur
 * @expect No crashes; success/failure matches reference model
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int macAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefCmacModel    ref;
    CRYPT_CMAC_Ctx *mac = NULL;
    uint32_t        prng = (uint32_t)seed;
    int32_t         ret;
    RefCmacResult   exp;

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)((i * seed) & 0xFF);

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)((i * 7 + seed) & 0xFF);

    uint8_t out[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefCmac_ModelInit(&ref);
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    bool initialized = false;

    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prng) % 5;

        switch (op) {
            case 0: /* Init */
                exp = RefCmac_Init(&ref, true);
                if (!initialized) {
                    ret = CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId));
                    initialized = true;
                } else {
                    ret = CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId));
                }
                break;
            case 1: /* Update */
                exp = RefCmac_Update(&ref, 64, true);
                ret = initialized ? CRYPT_CMAC_Update(mac, msg, 64) : (int32_t)CRYPT_EAL_ERR_STATE;
                break;
            case 2: /* Final */
                exp = RefCmac_Final(&ref, true);
                if (initialized) {
                    outLen = sizeof(out);
                    ret = CRYPT_CMAC_Final(mac, out, &outLen);
                } else {
                    ret = CRYPT_EAL_ERR_STATE;
                }
                break;
            case 3: /* Reinit */
                exp = RefCmac_Reinit(&ref);
                ret = initialized ? CRYPT_CMAC_Reinit(mac) : (int32_t)CRYPT_EAL_ERR_STATE;
                break;
            case 4: /* Deinit */
                exp = RefCmac_Deinit(&ref);
                ret = CRYPT_CMAC_Deinit(mac);
                break;
            default:
                continue;
        }

        if (exp.success) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
        }
    }

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_CMAC_STATE_MACHINE_NULL_PARAMS_TC001
 * @title Verify CMAC handles NULL parameters correctly
 * @precon nan
 * @brief
 *  1.All operations with NULL ctx → CRYPT_NULL_INPUT
 *  2.Init with NULL key and len > 0 → should fail
 *  3.Update with NULL in and len > 0 → should fail
 * @expect NULL parameters return CRYPT_NULL_INPUT
 */
/* BEGIN_CASE */
void SDV_CMAC_STATE_MACHINE_NULL_PARAMS_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_CMAC_Ctx *mac = NULL;
    uint8_t key[32] = {0};
    uint8_t msg[64] = {0};
    uint8_t out[CMAC_TEST_MAX_OUT_SIZE];
    uint32_t outLen = sizeof(out);

    /* NULL ctx */
    ASSERT_EQ(CRYPT_CMAC_Init(NULL, key, GetCmacKeyLen(macAlgId)), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_CMAC_Update(NULL, msg, 64),    CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_CMAC_Final(NULL, out, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_CMAC_Reinit(NULL),              CRYPT_NULL_INPUT);
    CRYPT_EAL_MacDeinit(NULL);  /* void, accepts NULL gracefully */
    ASSERT_TRUE(CRYPT_CMAC_DupCtx(NULL) == NULL);

    /* NULL key with nonzero length */
    mac = CRYPT_CMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_CMAC_Init(mac, NULL, 16), CRYPT_NULL_INPUT);

    /* NULL data with nonzero length after valid Init */
    ASSERT_EQ(CRYPT_CMAC_Init(mac, key, GetCmacKeyLen(macAlgId)), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_CMAC_Update(mac, NULL, 64), CRYPT_SUCCESS);

EXIT:
    CRYPT_CMAC_FreeCtx(mac);
    return;
}
/* END_CASE */
