/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
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
#include "crypt_hmac.h"

/* END_HEADER */

#define HMAC_INTERNAL_MAX_KEY_SIZE 256
#define HMAC_INTERNAL_MAX_MSG_SIZE 1024
#define HMAC_INTERNAL_MAX_MAC_SIZE 64
#define HMAC_INTERNAL_MAX_OPS 100

/* ============================================================================
 * REFERENCE MODEL FOR HMAC INTERNAL STATE MACHINE
 * Tracks state through Init, Update, Final, Reinit, Deinit, DupCtx
 * ============================================================================ */

typedef enum {
    REF_HMAC_STATE_NEW = 0,
    REF_HMAC_STATE_INIT = 1,
    REF_HMAC_STATE_UPDATE = 2,
    REF_HMAC_STATE_FINAL = 3,
    REF_HMAC_STATE_DEINIT = 4
} RefHmacInternalState;

typedef struct {
    RefHmacInternalState state;
    uint32_t updateCount;
    uint32_t totalMsgLen;
    uint32_t macLen;
} RefHmacInternalModel;

static void RefHmacInternal_Init(RefHmacInternalModel *model, uint32_t macLen)
{
    model->state = REF_HMAC_STATE_NEW;
    model->updateCount = 0;
    model->totalMsgLen = 0;
    model->macLen = macLen;
}

typedef struct {
    int32_t retCode;
    RefHmacInternalState stateBefore;
    RefHmacInternalState stateAfter;
    bool success;
} RefHmacInternalResult;

static RefHmacInternalResult RefHmacInternal_DoInit(RefHmacInternalModel *model, bool willSucceed)
{
    RefHmacInternalResult result = {0};
    result.stateBefore = model->state;

    if (model->state == REF_HMAC_STATE_INIT || model->state == REF_HMAC_STATE_UPDATE) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }

    if (willSucceed) {
        model->state = REF_HMAC_STATE_INIT;
        model->updateCount = 0;
        model->totalMsgLen = 0;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }

    result.stateAfter = model->state;
    return result;
}

static RefHmacInternalResult RefHmacInternal_DoUpdate(RefHmacInternalModel *model, uint32_t msgLen, bool willSucceed)
{
    RefHmacInternalResult result = {0};
    result.stateBefore = model->state;

    if (model->state != REF_HMAC_STATE_INIT && model->state != REF_HMAC_STATE_UPDATE) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }

    if (willSucceed) {
        model->state = REF_HMAC_STATE_UPDATE;
        model->updateCount++;
        model->totalMsgLen += msgLen;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }

    result.stateAfter = model->state;
    return result;
}

static RefHmacInternalResult RefHmacInternal_DoFinal(RefHmacInternalModel *model, bool willSucceed)
{
    RefHmacInternalResult result = {0};
    result.stateBefore = model->state;

    if (model->state != REF_HMAC_STATE_INIT && model->state != REF_HMAC_STATE_UPDATE) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }

    if (willSucceed) {
        model->state = REF_HMAC_STATE_FINAL;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }

    result.stateAfter = model->state;
    return result;
}

static RefHmacInternalResult RefHmacInternal_DoReinit(RefHmacInternalModel *model, bool willSucceed)
{
    RefHmacInternalResult result = {0};
    result.stateBefore = model->state;

    if (model->state != REF_HMAC_STATE_UPDATE && model->state != REF_HMAC_STATE_FINAL) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }

    if (willSucceed) {
        model->state = REF_HMAC_STATE_INIT;
        model->updateCount = 0;
        model->totalMsgLen = 0;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }

    result.stateAfter = model->state;
    return result;
}

static RefHmacInternalResult RefHmacInternal_DoDeinit(RefHmacInternalModel *model)
{
    RefHmacInternalResult result = {0};
    result.stateBefore = model->state;

    model->state = REF_HMAC_STATE_DEINIT;
    model->updateCount = 0;
    model->totalMsgLen = 0;
    result.retCode = CRYPT_SUCCESS;
    result.success = true;

    result.stateAfter = model->state;
    return result;
}

static uint32_t GetHmacMacLen(int macAlgId)
{
    switch (macAlgId) {
    case CRYPT_MAC_HMAC_SHA1:
        return 20;
    case CRYPT_MAC_HMAC_SHA224:
        return 28;
    case CRYPT_MAC_HMAC_SHA256:
        return 32;
    case CRYPT_MAC_HMAC_SHA384:
        return 48;
    case CRYPT_MAC_HMAC_SHA512:
        return 64;
    default:
        return 0;
    }
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_HMAC_INTERNAL_DUP_THEN_COMPUTE_TC001
 * @title Verify DupCtx produces a context that computes identical MAC
 * @precon nan
 * @brief
 * 1.Create HMAC, Init with key, Update with message, Final -> out1
 * 2.DupCtx the original context at UPDATE state
 * 3.Final on the dup'd context -> out2
 * 4.Verify out1 == out2
 * @expect
 * DupCtx produces a fully functional copy that gives identical results
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DUP_THEN_COMPUTE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *dup = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 5 + 11);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg, 64), CRYPT_SUCCESS);

    dup = CRYPT_HMAC_DupCtx(mac);
    ASSERT_TRUE(dup != NULL);

    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(outLen1, expectedMacLen);

    ASSERT_EQ(CRYPT_HMAC_Final(dup, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, expectedMacLen);

    ASSERT_EQ(memcmp(out1, out2, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(dup);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DUP_INDEPENDENT_TC001
 * @title Verify DupCtx produces independent context
 * @precon nan
 * @brief
 * 1.Create HMAC, Init, Update(msg1)
 * 2.DupCtx the context
 * 3.On original: Final -> out1, Reinit, Update(msg2), Final -> out2
 * 4.On dup: Final -> out3
 * 5.Verify out1 == out3 (dup was made at same state)
 * 6.Verify out1 != out2 (original state changed independently)
 * @expect
 * Dup'd context is independent of original
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DUP_INDEPENDENT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *dup = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);

    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 11 + 5);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out3[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    uint32_t outLen3 = sizeof(out3);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg1, 64), CRYPT_SUCCESS);

    dup = CRYPT_HMAC_DupCtx(mac);
    ASSERT_TRUE(dup != NULL);

    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Reinit(mac), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out2, &outLen2), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_HMAC_Final(dup, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out1, out3, expectedMacLen), 0);
    ASSERT_NE(memcmp(out1, out2, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(dup);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001
 * @title Verify HMAC Update fails after Deinit
 * @precon nan
 * @brief
 * 1.Create HMAC, Init, Update, Final
 * 2.Call Deinit
 * 3.Call Update - should fail (state is DEINIT)
 * @expect
 * Update after Deinit returns error
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacInternalModel refModel;
    CRYPT_HMAC_Ctx *mac = NULL;
    RefHmacInternalResult refResult;
    int32_t implRet;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    RefHmacInternal_Init(&refModel, GetHmacMacLen(macAlgId));

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefHmacInternal_DoInit(&refModel, true);
    implRet = CRYPT_HMAC_Init(mac, key, 32);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefHmacInternal_DoUpdate(&refModel, 64, true);
    implRet = CRYPT_HMAC_Update(mac, msg, 64);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefHmacInternal_DoFinal(&refModel, true);
    implRet = CRYPT_HMAC_Final(mac, out, &outLen);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefHmacInternal_DoDeinit(&refModel);
    CRYPT_HMAC_Deinit(mac);

    refResult = RefHmacInternal_DoUpdate(&refModel, 64, true);
    implRet = CRYPT_HMAC_Update(mac, msg, 64);
    ASSERT_NE(implRet, CRYPT_SUCCESS);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001
 * @title Verify HMAC Reinit after Deinit requires re-Init
 * @precon nan
 * @brief
 * 1.Create HMAC, Init, Update, Final
 * 2.Call Deinit
 * 3.Call Reinit - should fail or require re-Init
 * 4.Call Init - should succeed
 * 5.Verify full computation after re-Init
 * @expect
 * After Deinit, Reinit alone is insufficient; must re-Init
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out, &outLen), CRYPT_SUCCESS);

    CRYPT_HMAC_Deinit(mac);

    int32_t reinitRet = CRYPT_HMAC_Reinit(mac);

    int32_t updateRet = CRYPT_HMAC_Update(mac, msg, 64);

    if (reinitRet == CRYPT_SUCCESS && updateRet == CRYPT_SUCCESS) {
        uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
        uint32_t outLen2 = sizeof(out2);
        int32_t finalRet = CRYPT_HMAC_Final(mac, out2, &outLen2);
        ASSERT_NE(finalRet, CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, expectedMacLen);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_REINIT_RESETS_HASH_TC001
 * @title Verify HMAC Reinit produces same result as fresh Init with same key
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key), Update(msg1), Final -> out1
 * 2.Reinit, Update(msg2), Final -> out2
 * 3.Create fresh HMAC, Init(key), Update(msg2), Final -> out3
 * 4.Verify out2 == out3
 * @expect
 * Reinit resets internal hash state to post-Init state
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_REINIT_RESETS_HASH_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac1 = NULL;
    CRYPT_HMAC_Ctx *mac2 = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 23);

    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 7 + 13);

    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out3[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen2 = sizeof(out2);
    uint32_t outLen3 = sizeof(out3);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac1 = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac1, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac1, msg1, 64), CRYPT_SUCCESS);
    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    ASSERT_EQ(CRYPT_HMAC_Final(mac1, out1, &outLen1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_HMAC_Reinit(mac1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac1, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac1, out2, &outLen2), CRYPT_SUCCESS);

    mac2 = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac2, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac2, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac2, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out2, out3, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac1);
    CRYPT_HMAC_FreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_REINIT_FROM_NEW_TC001
 * @title Verify HMAC Reinit from NEW state fails
 * @precon nan
 * @brief
 * 1.Create HMAC context (state is NEW, no Init called)
 * 2.Call Reinit - should fail
 * @expect
 * Reinit from NEW state returns error
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_REINIT_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacInternalModel refModel;
    CRYPT_HMAC_Ctx *mac = NULL;
    RefHmacInternalResult refResult;
    int32_t implRet;

    RefHmacInternal_Init(&refModel, GetHmacMacLen(macAlgId));

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefHmacInternal_DoReinit(&refModel, true);
    implRet = CRYPT_HMAC_Reinit(mac);
    ASSERT_NE(implRet, CRYPT_SUCCESS);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_UPDATE_FROM_NEW_TC001
 * @title Verify HMAC Update from NEW state fails
 * @precon nan
 * @brief
 * 1.Create HMAC context (state is NEW)
 * 2.Call Update - should fail
 * @expect
 * Update from NEW state returns error
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_UPDATE_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    int32_t ret = CRYPT_HMAC_Update(mac, msg, 64);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_FINAL_FROM_NEW_TC001
 * @title Verify HMAC Final from NEW state fails
 * @precon nan
 * @brief
 * 1.Create HMAC context (state is NEW)
 * 2.Call Final - should fail
 * @expect
 * Final from NEW state returns error
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_FINAL_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;

    uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    int32_t ret = CRYPT_HMAC_Final(mac, out, &outLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DUP_FROM_NEW_TC001
 * @title Verify DupCtx from NEW state
 * @precon nan
 * @brief
 * 1.Create HMAC context (state is NEW, no Init called)
 * 2.Call DupCtx - should return NULL or a context that requires Init
 * 3.If non-NULL dup, try Update on dup - should fail
 * @expect
 * DupCtx from NEW state either fails or produces unusable context
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DUP_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *dup = NULL;

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    dup = CRYPT_HMAC_DupCtx(mac);

    if (dup != NULL) {
        int32_t ret = CRYPT_HMAC_Update(dup, msg, 64);
        ASSERT_NE(ret, CRYPT_SUCCESS);

        uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
        uint32_t outLen = sizeof(out);
        ret = CRYPT_HMAC_Final(dup, out, &outLen);
        ASSERT_NE(ret, CRYPT_SUCCESS);
    }

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(dup);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DUP_THEN_REINIT_TC001
 * @title Verify DupCtx copy can be reinitialized independently
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key), Update(msg1)
 * 2.DupCtx
 * 3.On original: Final -> out1
 * 4.On dup: Reinit, Update(msg2), Final -> out2
 * 5.Create fresh, Init(key), Update(msg2), Final -> out3
 * 6.Verify out2 == out3
 * @expect
 * Dup'd context supports Reinit and produces correct results
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DUP_THEN_REINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *dup = NULL;
    CRYPT_HMAC_Ctx *fresh = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 5 + 11);

    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 13 + 3);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out3[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    uint32_t outLen3 = sizeof(out3);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg1, 64), CRYPT_SUCCESS);

    dup = CRYPT_HMAC_DupCtx(mac);
    ASSERT_TRUE(dup != NULL);

    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_HMAC_Reinit(dup), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(dup, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(dup, out2, &outLen2), CRYPT_SUCCESS);

    fresh = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(fresh, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(fresh, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(fresh, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out2, out3, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(dup);
    CRYPT_HMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_MULTI_REINIT_TC001
 * @title Verify multiple Reinit calls maintain correctness
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key)
 * 2.Loop 10 times: Update(msg), Final -> out_i, Reinit
 * 3.Verify all outputs are identical
 * @expect
 * Multiple Reinit cycles produce deterministic, correct results
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_MULTI_REINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 11 + 7);

    uint8_t refOut[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t refOutLen = sizeof(refOut);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);

    for (int iter = 0; iter < 10; iter++) {
        ASSERT_EQ(CRYPT_HMAC_Update(mac, msg, 64), CRYPT_SUCCESS);

        uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
        uint32_t outLen = sizeof(out);
        ASSERT_EQ(CRYPT_HMAC_Final(mac, out, &outLen), CRYPT_SUCCESS);

        if (iter == 0) {
            memcpy(refOut, out, refOutLen);
        } else {
            ASSERT_EQ(memcmp(out, refOut, GetHmacMacLen(macAlgId)), 0);
        }

        ASSERT_EQ(CRYPT_HMAC_Reinit(mac), CRYPT_SUCCESS);
    }

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DEINIT_THEN_INIT_TC001
 * @title Verify Init after Deinit restores full functionality
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key1), Update(msg1), Final -> out1
 * 2.Deinit
 * 3.Init(key2), Update(msg2), Final -> out2
 * 4.Create fresh HMAC, Init(key2), Update(msg2), Final -> out3
 * 5.Verify out2 == out3
 * @expect
 * Init after Deinit fully restores the context
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DEINIT_THEN_INIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *fresh = NULL;

    uint8_t key1[32] = {0};
    for (int i = 0; i < 32; i++) key1[i] = (uint8_t)(i + 1);

    uint8_t key2[32] = {0};
    for (int i = 0; i < 32; i++) key2[i] = (uint8_t)(i * 3 + 5);

    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)i;

    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 7);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out3[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    uint32_t outLen3 = sizeof(out3);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key1, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg1, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);

    CRYPT_HMAC_Deinit(mac);

    ASSERT_EQ(CRYPT_HMAC_Init(mac, key2, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, expectedMacLen);

    fresh = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(fresh, key2, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(fresh, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(fresh, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out2, out3, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_DUP_AT_FINAL_TC001
 * @title Verify DupCtx at FINAL state and subsequent Reinit
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key), Update(msg), Final -> out1
 * 2.DupCtx at FINAL state
 * 3.On dup: Reinit, Update(msg), Final -> out2
 * 4.Verify out1 == out2 (same key, same message after reinit)
 * @expect
 * DupCtx at FINAL state produces a valid copy that supports Reinit
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_DUP_AT_FINAL_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *dup = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 5 + 3);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 9 + 2);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);

    dup = CRYPT_HMAC_DupCtx(mac);
    ASSERT_TRUE(dup != NULL);

    ASSERT_EQ(CRYPT_HMAC_Reinit(dup), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(dup, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(dup, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, expectedMacLen);

    ASSERT_EQ(memcmp(out1, out2, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(dup);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_NULL_CTX_TC001
 * @title Verify HMAC internal API handles NULL context
 * @precon nan
 * @brief
 * 1.Call all internal HMAC functions with NULL ctx
 * 2.Verify each returns appropriate error
 * @expect
 * NULL ctx is handled gracefully
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_NULL_CTX_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t key[32] = {0};
    uint8_t msg[64] = {0};
    uint8_t out[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    ASSERT_EQ(CRYPT_HMAC_Init(NULL, key, 32), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_HMAC_Update(NULL, msg, 64), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_HMAC_Final(NULL, out, &outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_HMAC_Reinit(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_HMAC_Deinit(NULL), CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_HMAC_DupCtx(NULL) == NULL);
    ASSERT_EQ(CRYPT_HMAC_GetMacLen(NULL), 0);

    EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001
 * @title Verify HMAC Reinit from INIT state
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key) - state is INIT
 * 2.Call Reinit from INIT state
 * 3.Verify result matches reference model
 * @expect
 * Reinit from INIT state should return error (no data processed yet)
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacInternalModel refModel;
    CRYPT_HMAC_Ctx *mac = NULL;
    RefHmacInternalResult refResult;
    int32_t implRet;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    RefHmacInternal_Init(&refModel, GetHmacMacLen(macAlgId));

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    RefHmacInternalResult initResult = RefHmacInternal_DoInit(&refModel, true);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), initResult.retCode);

    refResult = RefHmacInternal_DoReinit(&refModel, true);
    implRet = CRYPT_HMAC_Reinit(mac);

    if (refResult.retCode != CRYPT_SUCCESS) {
        ASSERT_NE(implRet, CRYPT_SUCCESS);
    }

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_INTERNAL_KEY_REUSE_SAFETY_TC001
 * @title Verify HMAC key is properly isolated after Reinit
 * @precon nan
 * @brief
 * 1.Create HMAC, Init(key), Update(secret_msg), Final -> out1
 * 2.Reinit, Update(different_msg), Final -> out2
 * 3.Verify out1 != out2 and out2 is correct
 * 4.Verify key material from first computation cannot affect second
 * @expect
 * Reinit properly isolates computations
 */
/* BEGIN_CASE */
void SDV_HMAC_INTERNAL_KEY_REUSE_SAFETY_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_HMAC_Ctx *mac = NULL;
    CRYPT_HMAC_Ctx *fresh = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 17 + 31);

    uint8_t msg1[128] = {0};
    for (int i = 0; i < 128; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[32] = {0};
    for (int i = 0; i < 32; i++) msg2[i] = (uint8_t)(i * 7 + 11);

    uint8_t out1[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out2[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint8_t out3[HMAC_INTERNAL_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    uint32_t outLen3 = sizeof(out3);

    uint32_t expectedMacLen = GetHmacMacLen(macAlgId);

    mac = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg1, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out1, &outLen1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_HMAC_Reinit(mac), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(mac, msg2, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(mac, out2, &outLen2), CRYPT_SUCCESS);

    fresh = CRYPT_HMAC_NewCtx(macAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_HMAC_Init(fresh, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Update(fresh, msg2, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_HMAC_Final(fresh, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_NE(memcmp(out1, out2, expectedMacLen), 0);
    ASSERT_EQ(memcmp(out2, out3, expectedMacLen), 0);

    EXIT:
    CRYPT_HMAC_FreeCtx(mac);
    CRYPT_HMAC_FreeCtx(fresh);
    return;
}
/* END_CASE */
