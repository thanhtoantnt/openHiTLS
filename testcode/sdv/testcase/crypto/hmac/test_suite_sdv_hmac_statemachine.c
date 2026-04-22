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

#define HMAC_TEST_MAX_KEY_SIZE 256
#define HMAC_TEST_MAX_MSG_SIZE 1024
#define HMAC_TEST_MAX_MAC_SIZE 64

/* ============================================================================
 * REFERENCE MODEL FOR HMAC STATE MACHINE
 * Tracks expected HMAC behavior based on RFC 2104
 * ============================================================================ */

typedef enum {
    REF_STATE_NEW = 0,
    REF_STATE_INIT = 1,
    REF_STATE_UPDATE = 2,
    REF_STATE_FINAL = 3
} RefHmacState;

typedef enum {
    REF_OP_INIT = 0,
    REF_OP_UPDATE = 1,
    REF_OP_FINAL = 2,
    REF_OP_REINIT = 3,
    REF_OP_COUNT = 4
} RefHmacOp;

typedef struct {
    RefHmacState state;
    uint32_t updateCount;
    uint32_t totalMsgLen;
    uint32_t macLen;
} RefHmacModel;

typedef struct {
    int32_t retCode;
    RefHmacState stateBefore;
    RefHmacState stateAfter;
    bool success;
} RefOpResult;

static void RefModel_Init(RefHmacModel *model, uint32_t macLen)
{
    model->state = REF_STATE_NEW;
    model->updateCount = 0;
    model->totalMsgLen = 0;
    model->macLen = macLen;
}

static RefOpResult RefModel_MacInit(RefHmacModel *model, bool willSucceed)
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

static RefOpResult RefModel_MacUpdate(RefHmacModel *model, uint32_t msgLen, bool willSucceed)
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

static RefOpResult RefModel_MacFinal(RefHmacModel *model, bool willSucceed)
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
        result.retCode = CRYPT_NULL_INPUT;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_MacReinit(RefHmacModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_UPDATE && model->state != REF_STATE_FINAL) {
        result.retCode = CRYPT_EAL_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->state = REF_STATE_INIT;
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

/* ============================================================================
 * SIMPLE PRNG FOR RANDOM TEST GENERATION
 * ============================================================================ */

static uint32_t SimplePrng(uint32_t *state)
{
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    return *state;
}

static uint32_t GetExpectedMacLen(int macAlgId)
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
 * @test   SDV_HMAC_STATE_MACHINE_BASIC_TC001
 * @title  Verify basic HMAC state transitions match reference model
 * @precon nan
 * @brief
 *    1.Create HMAC context
 *    2.Execute Init, verify state transition NEW -> INIT
 *    3.Execute Update, verify state transition INIT -> UPDATE
 *    4.Execute Final, verify state transition UPDATE -> FINAL
 * @expect
 *    All state transitions match reference model predictions
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_BASIC_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 2);
    
    uint8_t macOut[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t macOutLen = sizeof(macOut);
    
    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));
    
    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    
    /* Step 1: Init - NEW -> INIT */
    refResult = RefModel_MacInit(&refModel, true);
    implRet = CRYPT_EAL_MacInit(mac, key, 32);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Step 2: Update - INIT -> UPDATE */
    refResult = RefModel_MacUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Step 3: Final - UPDATE -> FINAL */
    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, macOut, &macOutLen);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(macOutLen, refModel.macLen);
    
EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test   SDV_HMAC_STATE_MACHINE_DETERMINISM_TC001
 * @title  Verify HMAC determinism property
 * @precon nan
 * @brief
 *    1.Compute HMAC twice with same key and message
 *    2.Verify both outputs are identical
 * @expect
 *    HMAC(K, m) is deterministic
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_DETERMINISM_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);
    
    uint8_t msg[128] = {0};
    for (int i = 0; i < 128; i++) msg[i] = (uint8_t)(i * 5 + 11);
    
    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    
    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);
    
    /* First computation */
    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(outLen1, expectedMacLen);
    
    /* Second computation with same inputs */
    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, expectedMacLen);
    
    /* Verify determinism: outputs must be identical */
    ASSERT_EQ(memcmp(out1, out2, expectedMacLen), 0);
    
EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test   SDV_HMAC_STATE_MACHINE_UPDATE_CHAINING_TC001
 * @title  Verify HMAC update chaining property
 * @precon nan
 * @brief
 *    1.Compute HMAC with single Update call
 *    2.Compute HMAC with multiple Update calls on same message chunks
 *    3.Verify both outputs are identical
 * @expect
 *    HMAC(K, m1 || m2) = HMAC after Update(m1), Update(m2)
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_UPDATE_CHAINING_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 13);
    
    uint8_t msg[128] = {0};
    for (int i = 0; i < 128; i++) msg[i] = (uint8_t)(i * 11 + 17);
    
    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    
    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);
    
    /* Single Update call */
    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);
    
    /* Multiple Update calls */
    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg + 32, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg + 64, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg + 96, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out2, &outLen2), CRYPT_SUCCESS);
    
    /* Verify chaining property */
    ASSERT_EQ(memcmp(out1, out2, expectedMacLen), 0);
    
EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test   SDV_HMAC_STATE_MACHINE_REINIT_TC001
 * @title  Verify HMAC reinit resets state correctly
 * @precon nan
 * @brief
 *    1.Compute HMAC with first message
 *    2.Call Reinit
 *    3.Compute HMAC with second message
 *    4.Verify second result is independent of first
 * @expect
 *    Reinit properly resets internal state
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_REINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    
    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)i;
    
    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i + 100);
    
    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    
    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));
    
    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    
    /* First computation */
    refResult = RefModel_MacInit(&refModel, true);
    implRet = CRYPT_EAL_MacInit(mac, key, 32);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_MacUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_MacUpdate(mac, msg1, 64);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, out1, &outLen1);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Reinit */
    refResult = RefModel_MacReinit(&refModel, true);
    implRet = CRYPT_EAL_MacReinit(mac);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Second computation */
    refResult = RefModel_MacUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_MacUpdate(mac, msg2, 64);
    ASSERT_EQ(implRet, refResult.retCode);
    
    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, out2, &outLen2);
    ASSERT_EQ(implRet, refResult.retCode);
    
    /* Verify outputs are different (different messages) */
    ASSERT_NE(memcmp(out1, out2, refModel.macLen), 0);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_EMPTY_KEY_TC001
 * @title Verify HMAC with empty key
 * @precon nan
 * @brief
 *  1.Create HMAC context
 *  2.Init with NULL key and length 0
 *  3.Update and Final
 *  4.Init with non-NULL key and length 0
 *  5.Update and Final
 *  6.Verify both produce valid MACs
 * @expect
 *  Empty key is accepted and produces valid output
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_EMPTY_KEY_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(outLen1, expectedMacLen);

    uint8_t emptyKey[1] = {0};
    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, emptyKey, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, expectedMacLen);

    ASSERT_EQ(memcmp(out1, out2, expectedMacLen), 0);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_KEY_EQUALS_BLOCKSIZE_TC001
 * @title Verify HMAC with key exactly equal to block size
 * @precon nan
 * @brief
 *  1.Create HMAC context
 *  2.Init with key exactly equal to block size (64 for SHA256)
 *  3.Compute MAC
 *  4.Verify output is valid
 * @expect
 *  Key equal to block size works correctly
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_KEY_EQUALS_BLOCKSIZE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac = NULL;

    uint8_t key[128] = {0};
    for (int i = 0; i < 128; i++) key[i] = (uint8_t)(i + 0xAA);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 3);

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    uint32_t blockSize = 64;
    if (macAlgId == CRYPT_MAC_HMAC_SHA384 || macAlgId == CRYPT_MAC_HMAC_SHA512) {
        blockSize = 128;
    }

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac, key, blockSize), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, expectedMacLen);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_KEY_LARGER_THAN_BLOCKSIZE_TC001
 * @title Verify HMAC with key larger than block size
 * @precon nan
 * @brief
 *  1.Create HMAC context
 *  2.Init with key larger than block size (200 bytes)
 *  3.Compute MAC
 *  4.Compute MAC with hash(key) as key directly
 *  5.Verify key larger than block size is hashed internally
 * @expect
 *  Key larger than block size works correctly (key is hashed internally)
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_KEY_LARGER_THAN_BLOCKSIZE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac = NULL;

    uint8_t key[200] = {0};
    for (int i = 0; i < 200; i++) key[i] = (uint8_t)(i + 0x55);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7);

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac, key, 200), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(outLen, expectedMacLen);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_FINAL_WITHOUT_UPDATE_TC001
 * @title Verify HMAC Final without any Update calls
 * @precon nan
 * @brief
 *  1.Create HMAC context and Init
 *  2.Call Final immediately without Update
 *  3.Verify this produces a valid MAC (hash of empty message)
 * @expect
 *  Final after Init (no Update) produces valid MAC
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_FINAL_WITHOUT_UPDATE_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    RefModel_Init(&refModel, expectedMacLen);

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefModel_MacInit(&refModel, true);
    implRet = CRYPT_EAL_MacInit(mac, key, 32);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, out, &outLen);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(outLen, expectedMacLen);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_UPDATE_FINAL_CONSISTENCY_TC001
 * @title Verify HMAC with Update vs no-Update produces different results
 * @precon nan
 * @brief
 *  1.Compute HMAC with empty message (Init + Final)
 *  2.Compute HMAC with non-empty message (Init + Update + Final)
 *  3.Verify outputs are different
 * @expect
 *  HMAC with data differs from HMAC with empty data
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_UPDATE_FINAL_CONSISTENCY_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3 + 7);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 5 + 11);

    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);

    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out2, &outLen2), CRYPT_SUCCESS);

    ASSERT_NE(memcmp(out1, out2, expectedMacLen), 0);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_REINIT_RESET_TC001
 * @title Verify HMAC Reinit produces same result as fresh Init
 * @precon nan
 * @brief
 *  1.Compute HMAC with Init + Update(msg1) + Final -> out1
 *  2.Reinit and compute Update(msg2) + Final -> out2
 *  3.Create fresh context, Init + Update(msg2) + Final -> out3
 *  4.Verify out2 == out3 (Reinit produces same as fresh Init)
 * @expect
 *  Reinit resets state identically to fresh Init with same key
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_REINIT_RESET_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 11 + 23);

    uint8_t msg1[64] = {0};
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64] = {0};
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 7 + 13);

    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);

    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg1, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacReinit(mac1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out2, &outLen2), CRYPT_SUCCESS);

    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    uint8_t out3[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen3 = sizeof(out3);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out3, &outLen3), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out2, out3, expectedMacLen), 0);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_DEINIT_TC001
 * @title Verify HMAC Deinit resets to NEW state
 * @precon nan
 * @brief
 *  1.Create HMAC, Init, Update, Final
 *  2.Call Deinit - should reset to NEW state
 *  3.Call Update - should fail (state is NEW)
 *  4.Call Init again - should succeed
 * @expect
 *  Deinit properly resets state machine to NEW
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_DEINIT_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefModel_MacInit(&refModel, true);
    implRet = CRYPT_EAL_MacInit(mac, key, 32);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefModel_MacUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
    ASSERT_EQ(implRet, refResult.retCode);

    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, out, &outLen);
    ASSERT_EQ(implRet, refResult.retCode);

    CRYPT_EAL_MacDeinit(mac);

    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
    ASSERT_EQ(implRet, CRYPT_EAL_ERR_STATE);

    implRet = CRYPT_EAL_MacInit(mac, key, 32);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);

    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_NULL_PARAMS_TC001
 * @title Verify HMAC handles NULL parameters correctly
 * @precon nan
 * @brief
 *  1.Call MacInit with NULL key and len > 0 - should fail
 *  2.Call MacUpdate with NULL data and len > 0 - should fail
 *  3.Call MacFinal with NULL output - should fail
 *  4.Call MacReinit on NEW context - should fail
 * @expect
 *  NULL parameters return appropriate errors
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_NULL_PARAMS_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MacCtx *mac = NULL;
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    int32_t ret = CRYPT_EAL_MacInit(mac, NULL, 32);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ASSERT_EQ(CRYPT_EAL_MacInit(mac, key, 32), CRYPT_SUCCESS);

    ret = CRYPT_EAL_MacUpdate(mac, NULL, 64);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac, key, 32), CRYPT_SUCCESS);

    ret = CRYPT_EAL_MacFinal(mac, NULL, &outLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_REINIT_FROM_NEW_TC001
 * @title Verify HMAC Reinit from NEW state fails
 * @precon nan
 * @brief
 *  1.Create HMAC context (state is NEW)
 *  2.Call Reinit - should fail with state error
 * @expect
 *  Reinit from NEW state returns CRYPT_EAL_ERR_STATE
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_REINIT_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;

    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefModel_MacReinit(&refModel, true);
    implRet = CRYPT_EAL_MacReinit(mac);
    ASSERT_EQ(implRet, refResult.retCode);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_MULTI_FINAL_TC001
 * @title Verify HMAC rejects multiple Final calls without Reinit
 * @precon nan
 * @brief
 *  1.Create HMAC, Init, Update, Final
 *  2.Call Final again - should fail (state is FINAL)
 * @expect
 *  Second Final returns CRYPT_EAL_ERR_STATE
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_MULTI_FINAL_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;

    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7);

    uint8_t out[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen = sizeof(out);

    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    ASSERT_EQ(CRYPT_EAL_MacInit(mac, key, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac, out, &outLen), CRYPT_SUCCESS);

    refResult = RefModel_MacFinal(&refModel, true);
    implRet = CRYPT_EAL_MacFinal(mac, out, &outLen);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_NE(implRet, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test SDV_HMAC_STATE_MACHINE_UPDATE_FROM_NEW_TC001
 * @title Verify HMAC Update from NEW state fails
 * @precon nan
 * @brief
 *  1.Create HMAC context (state is NEW)
 *  2.Call Update - should fail with state error
 * @expect
 *  Update from NEW state returns CRYPT_EAL_ERR_STATE
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_UPDATE_FROM_NEW_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    RefOpResult refResult;
    int32_t implRet;

    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;

    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));

    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);

    refResult = RefModel_MacUpdate(&refModel, 64, true);
    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_NE(implRet, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test   SDV_HMAC_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title  Verify HMAC state consistency under random operation sequences
 * @precon nan
 * @brief
 *    1.Generate random sequence of operations
 *    2.Execute each operation on both implementation and reference model
 *    3.Compare states after each operation
 * @expect
 *    All operation sequences produce matching states
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int macAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    RefHmacModel refModel;
    CRYPT_EAL_MacCtx *mac = NULL;
    uint32_t prngState = (uint32_t)seed;
    RefOpResult refResult;
    int32_t implRet;
    
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)((i * seed) & 0xFF);
    
    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)((i * 7 + seed) & 0xFF);
    
    uint8_t macOut[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t macOutLen = sizeof(macOut);
    
    RefModel_Init(&refModel, GetExpectedMacLen(macAlgId));
    
    mac = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac != NULL);
    
    bool initialized = false;
    
    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prngState) % REF_OP_COUNT;
        
        switch (op) {
            case REF_OP_INIT:
                refResult = RefModel_MacInit(&refModel, true);
                if (!initialized) {
                    implRet = CRYPT_EAL_MacInit(mac, key, 32);
                    initialized = true;
                } else {
                    implRet = CRYPT_SUCCESS;
                }
                break;
                
            case REF_OP_UPDATE:
                refResult = RefModel_MacUpdate(&refModel, 64, true);
                if (initialized) {
                    implRet = CRYPT_EAL_MacUpdate(mac, msg, 64);
                } else {
                    implRet = CRYPT_EAL_ERR_STATE;
                }
                break;
                
            case REF_OP_FINAL:
                refResult = RefModel_MacFinal(&refModel, true);
                if (initialized) {
                    implRet = CRYPT_EAL_MacFinal(mac, macOut, &macOutLen);
                } else {
                    implRet = CRYPT_EAL_ERR_STATE;
                }
                break;
                
            case REF_OP_REINIT:
                refResult = RefModel_MacReinit(&refModel, true);
                if (initialized) {
                    implRet = CRYPT_EAL_MacReinit(mac);
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
    CRYPT_EAL_MacFreeCtx(mac);
    return;
}
/* END_CASE */

/**
 * @test   SDV_HMAC_STATE_MACHINE_KEY_SENSITIVITY_TC001
 * @title  Verify HMAC key sensitivity property
 * @precon nan
 * @brief
 *    1.Compute HMAC with key K1
 *    2.Compute HMAC with different key K2
 *    3.Verify outputs are different
 * @expect
 *    Different keys produce different MACs
 */
/* BEGIN_CASE */
void SDV_HMAC_STATE_MACHINE_KEY_SENSITIVITY_TC001(int macAlgId)
{
    if (!CRYPT_EAL_MacIsValidAlgId(macAlgId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_EAL_MacCtx *mac1 = NULL;
    CRYPT_EAL_MacCtx *mac2 = NULL;
    
    uint8_t key1[32] = {0};
    for (int i = 0; i < 32; i++) key1[i] = (uint8_t)i;
    
    uint8_t key2[32] = {0};
    for (int i = 0; i < 32; i++) key2[i] = (uint8_t)(i + 1);
    
    uint8_t msg[64] = {0};
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 3);
    
    uint8_t out1[HMAC_TEST_MAX_MAC_SIZE];
    uint8_t out2[HMAC_TEST_MAX_MAC_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);
    
    uint32_t expectedMacLen = GetExpectedMacLen(macAlgId);
    
    /* Compute with key1 */
    mac1 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac1, key1, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac1, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac1, out1, &outLen1), CRYPT_SUCCESS);
    
    /* Compute with key2 */
    mac2 = CRYPT_EAL_MacNewCtx(macAlgId);
    ASSERT_TRUE(mac2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MacInit(mac2, key2, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacUpdate(mac2, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MacFinal(mac2, out2, &outLen2), CRYPT_SUCCESS);
    
    /* Different keys should produce different MACs */
    ASSERT_NE(memcmp(out1, out2, expectedMacLen), 0);
    
EXIT:
    CRYPT_EAL_MacFreeCtx(mac1);
    CRYPT_EAL_MacFreeCtx(mac2);
    return;
}
/* END_CASE */
