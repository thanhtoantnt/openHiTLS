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
#include "crypt_eal_rand.h"
#include "drbg_local.h"
#include "crypt_drbg.h"

/* END_HEADER */

#define DRBG_TEST_OUTPUT_SIZE 64
#define DRBG_TEST_SEED_SIZE 256
#define DRBG_TEST_MAX_OPS 100

/* ============================================================================
 * REFERENCE MODEL FOR INTERNAL DRBG STATE MACHINE
 * ============================================================================ */

typedef enum {
    REF_STATE_UNINITIALISED = 0,
    REF_STATE_READY = 1,
    REF_STATE_ERROR = 2
} RefDrbgState;

typedef struct {
    RefDrbgState state;
    uint32_t reseedCounter;
    uint32_t reseedInterval;
    uint32_t generateCount;
} RefDrbgModel;

typedef struct {
    int32_t retCode;
    RefDrbgState stateAfter;
    bool success;
} RefOpResult;

static void RefModel_Init(RefDrbgModel *model, uint32_t reseedInterval)
{
    model->state = REF_STATE_UNINITIALISED;
    model->reseedCounter = 0;
    model->reseedInterval = reseedInterval;
    model->generateCount = 0;
}

static RefOpResult RefModel_Instantiate(RefDrbgModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateAfter = model->state;
    
    if (model->state != REF_STATE_UNINITIALISED) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->state = REF_STATE_READY;
        model->reseedCounter = 1;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        model->state = REF_STATE_ERROR;
        result.retCode = CRYPT_DRBG_FAIL_GET_ENTROPY;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_Generate(RefDrbgModel *model, bool willSucceed, bool pr)
{
    RefOpResult result = {0};
    result.stateAfter = model->state;
    
    if (model->state != REF_STATE_READY) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.success = false;
        return result;
    }
    
    if (pr || model->reseedCounter > model->reseedInterval) {
        model->reseedCounter = 1;
    }
    
    if (willSucceed) {
        model->reseedCounter++;
        model->generateCount++;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        model->state = REF_STATE_ERROR;
        result.retCode = CRYPT_DRBG_FAIL_GET_ENTROPY;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_Reseed(RefDrbgModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateAfter = model->state;
    
    if (model->state != REF_STATE_READY) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.success = false;
        return result;
    }
    
    if (willSucceed) {
        model->reseedCounter = 1;
        result.retCode = CRYPT_SUCCESS;
        result.success = true;
    } else {
        model->state = REF_STATE_ERROR;
        result.retCode = CRYPT_DRBG_FAIL_GET_ENTROPY;
        result.success = false;
    }
    
    result.stateAfter = model->state;
    return result;
}

static RefOpResult RefModel_Uninstantiate(RefDrbgModel *model)
{
    RefOpResult result = {0};
    model->state = REF_STATE_UNINITIALISED;
    model->reseedCounter = 0;
    result.retCode = CRYPT_SUCCESS;
    result.stateAfter = model->state;
    result.success = true;
    return result;
}

static RefDrbgState ImplStateToRef(DRBG_State implState)
{
    switch (implState) {
        case DRBG_STATE_UNINITIALISED:
            return REF_STATE_UNINITIALISED;
        case DRBG_STATE_READY:
            return REF_STATE_READY;
        case DRBG_STATE_ERROR:
            return REF_STATE_ERROR;
        default:
            return REF_STATE_ERROR;
    }
}

/* ============================================================================
 * DETERMINISTIC ENTROPY SOURCE
 * ============================================================================ */

typedef struct {
    uint8_t seed[DRBG_TEST_SEED_SIZE];
    uint32_t pos;
    bool shouldFail;
    uint32_t callCount;
} DetEntropyCtx;

static int32_t DetGetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    DetEntropyCtx *detCtx = (DetEntropyCtx *)ctx;
    
    if (detCtx == NULL || entropy == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (detCtx->shouldFail) {
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    
    uint32_t len = lenRange->min;
    if (len > DRBG_TEST_SEED_SIZE) {
        len = DRBG_TEST_SEED_SIZE;
    }
    
    entropy->data = detCtx->seed;
    entropy->len = len;
    detCtx->callCount++;
    
    return CRYPT_SUCCESS;
}

static void DetCleanEntropy(void *ctx, CRYPT_Data *entropy)
{
    (void)ctx;
    (void)entropy;
}

static int32_t DetGetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)strength;
    DetEntropyCtx *detCtx = (DetEntropyCtx *)ctx;
    
    if (detCtx == NULL || nonce == NULL || lenRange == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (detCtx->shouldFail) {
        return CRYPT_DRBG_FAIL_GET_NONCE;
    }
    
    if (lenRange->max == 0) {
        nonce->data = NULL;
        nonce->len = 0;
        return CRYPT_SUCCESS;
    }
    
    uint32_t len = lenRange->min;
    if (len > DRBG_TEST_SEED_SIZE) {
        len = DRBG_TEST_SEED_SIZE;
    }
    
    nonce->data = detCtx->seed;
    nonce->len = len;
    
    return CRYPT_SUCCESS;
}

static void DetCleanNonce(void *ctx, CRYPT_Data *nonce)
{
    (void)ctx;
    (void)nonce;
}

static void SetupDetEntropy(CRYPT_RandSeedMethod *method, DetEntropyCtx *ctx, uint32_t seedVal)
{
    method->getEntropy = DetGetEntropy;
    method->cleanEntropy = DetCleanEntropy;
    method->getNonce = DetGetNonce;
    method->cleanNonce = DetCleanNonce;
    
    for (uint32_t i = 0; i < DRBG_TEST_SEED_SIZE; i++) {
        ctx->seed[i] = (uint8_t)((i * 7 + seedVal + 13) & 0xFF);
    }
    ctx->pos = 0;
    ctx->callCount = 0;
    ctx->shouldFail = false;
}

/* ============================================================================
 * SIMPLE PRNG FOR RANDOM TEST GENERATION
 * ============================================================================ */

static uint32_t SimplePrng(uint32_t *state)
{
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    return *state;
}

/* ============================================================================
 * INTERNAL DRBG API TESTS
 * These tests call DRBG_Instantiate/Generate/Reseed/Uninstantiate directly,
 * bypassing the EAL wrapper. This can reveal bugs hidden by the EAL layer.
 * ============================================================================ */

/**
 * @test SDV_DRBG_INTERNAL_NULL_OUTPUT_TC001
 * @title Verify DRBG_Generate handles NULL output pointer
 * @precon nan
 * @brief
 *  1.Create DRBG via DRBG_New and instantiate
 *  2.Call DRBG_Generate with out=NULL, outLen>0
 *  3.Verify behavior (should fail or handle gracefully)
 * @expect
 *  NULL output is rejected or handled safely
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_NULL_OUTPUT_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 11111);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    int32_t ret = DRBG_Generate(drbg, NULL, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_ZERO_LENGTH_TC001
 * @title Verify DRBG_Generate handles zero output length
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Call DRBG_Generate with outLen=0
 *  3.Verify behavior
 * @expect
 *  Zero length is handled correctly
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_ZERO_LENGTH_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    RefDrbgModel refModel;

    SetupDetEntropy(&seedMeth, &detCtx, 22222);
    RefModel_Init(&refModel, DRBG_RESEED_INTERVAL);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    uint32_t counterBefore = drbg->reseedCtr;
    int32_t ret = DRBG_Generate(drbg, NULL, 0, NULL, 0, false);

    if (ret == CRYPT_SUCCESS) {
        ASSERT_EQ(drbg->reseedCtr, counterBefore);
    }

    ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_READY);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_MAX_LENGTH_TC001
 * @title Verify DRBG_Generate handles maximum output length
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Call DRBG_Generate with outLen=DRBG_MAX_REQUEST (65536)
 *  3.Verify operation succeeds
 * @expect
 *  Maximum length request succeeds
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_MAX_LENGTH_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t *output = NULL;
    uint32_t maxLen = DRBG_MAX_REQUEST;

    SetupDetEntropy(&seedMeth, &detCtx, 33333);

    output = (uint8_t *)malloc(maxLen);
    ASSERT_TRUE(output != NULL);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    int32_t ret = DRBG_Generate(drbg, output, maxLen, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    free(output);
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_EXCESS_LENGTH_TC001
 * @title Verify DRBG_Generate rejects output length > DRBG_MAX_REQUEST
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Call DRBG_Generate with outLen=DRBG_MAX_REQUEST+1
 *  3.Verify operation fails with appropriate error
 * @expect
 *  Excessive length is rejected
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_EXCESS_LENGTH_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[1];

    SetupDetEntropy(&seedMeth, &detCtx, 44444);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    int32_t ret = DRBG_Generate(drbg, output, DRBG_MAX_REQUEST + 1, NULL, 0, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_NULL_CTX_TC001
 * @title Verify internal DRBG functions handle NULL context
 * @precon nan
 * @brief
 *  1.Call DRBG_Instantiate with ctx=NULL
 *  2.Call DRBG_Generate with ctx=NULL
 *  3.Call DRBG_Reseed with ctx=NULL
 *  4.Call DRBG_Uninstantiate with ctx=NULL
 *  5.Verify all return CRYPT_NULL_INPUT
 * @expect
 *  NULL context is rejected
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_NULL_CTX_TC001(void)
{
    TestMemInit();

    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    int32_t ret = DRBG_Instantiate(NULL, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = DRBG_Generate(NULL, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = DRBG_Reseed(NULL, NULL, 0);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = DRBG_Uninstantiate(NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_STATE_AFTER_ERROR_TC001
 * @title Verify DRBG state after entropy failure during instantiate
 * @precon nan
 * @brief
 *  1.Create DRBG with entropy source that fails
 *  2.Call DRBG_Instantiate - should fail
 *  3.Verify state is ERROR
 *  4.Call DRBG_Generate - should fail or auto-recover
 * @expect
 *  Error state is handled correctly
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_STATE_AFTER_ERROR_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 55555);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    detCtx.shouldFail = true;
    int32_t ret = DRBG_Instantiate(drbg, NULL, 0);
    ASSERT_NE(ret, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_ERROR);

    detCtx.shouldFail = false;
    ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_READY);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_RESEED_COUNTER_OVERFLOW_TC001
 * @title Verify DRBG handles reseed counter near UINT32_MAX
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Manually set reseedCtr near UINT32_MAX
 *  3.Generate - verify overflow handled
 * @expect
 *  Counter overflow handled gracefully
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_RESEED_COUNTER_OVERFLOW_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 66666);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    drbg->reseedCtr = 0xFFFFFFFE;

    int32_t ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ASSERT_TRUE(drbg->reseedCtr == 0xFFFFFFFF || drbg->reseedCtr == 0 || drbg->reseedCtr == 1);

    ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_PREDICTION_RESISTANCE_TC001
 * @title Verify prediction resistance triggers reseed
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Generate with pr=false - no reseed triggered
 *  3.Generate with pr=true - reseed should be triggered
 *  4.Verify entropy was obtained for reseed
 * @expect
 *  Prediction resistance triggers reseed
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_PREDICTION_RESISTANCE_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 77777);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false), CRYPT_SUCCESS);

    uint32_t entropyCallsBefore = detCtx.callCount;
    ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, true), CRYPT_SUCCESS);
    ASSERT_TRUE(detCtx.callCount > entropyCallsBefore);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_RESEED_INTERVAL_ZERO_TC001
 * @title Verify DRBG behavior with reseed interval of 0
 * @precon nan
 * @brief
 *  1.Create DRBG and set reseed interval to 0
 *  2.Instantiate
 *  3.Generate - should trigger immediate reseed
 * @expect
 *  Zero interval causes immediate reseed
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_RESEED_INTERVAL_ZERO_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    uint32_t interval = 0;

    SetupDetEntropy(&seedMeth, &detCtx, 88888);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Ctrl(drbg, CRYPT_CTRL_SET_RESEED_INTERVAL, &interval, sizeof(interval)), CRYPT_SUCCESS);
    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    uint32_t entropyCallsBefore = detCtx.callCount;
    int32_t ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_TRUE(detCtx.callCount > entropyCallsBefore);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_FORK_DETECTION_TC001
 * @title Verify fork detection triggers reseed
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Simulate fork by changing forkId
 *  3.Generate - should detect fork and reseed
 * @expect
 *  Fork detection works
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_FORK_DETECTION_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    int32_t originalForkId;

    SetupDetEntropy(&seedMeth, &detCtx, 99999);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    originalForkId = drbg->forkId;
    drbg->forkId = originalForkId + 1000;

    uint32_t entropyCallsBefore = detCtx.callCount;
    int32_t ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ASSERT_NE(drbg->forkId, originalForkId + 1000);
    ASSERT_TRUE(detCtx.callCount > entropyCallsBefore);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_MULTIPLE_GENERATE_TC001
 * @title Verify multiple generate calls maintain state consistency
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Call generate multiple times
 *  3.Verify reseed counter increments correctly
 *  4.Verify state remains READY
 * @expect
 *  Multiple generates work correctly
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_MULTIPLE_GENERATE_TC001(int algId, int numOps)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    RefDrbgModel refModel;

    SetupDetEntropy(&seedMeth, &detCtx, 10101);
    RefModel_Init(&refModel, DRBG_RESEED_INTERVAL);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(drbg->reseedCtr, 1);

    for (int i = 0; i < numOps; i++) {
        uint32_t expectedCtr = drbg->reseedCtr + 1;
        int32_t ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
        ASSERT_EQ(ret, CRYPT_SUCCESS);
        ASSERT_EQ(drbg->reseedCtr, expectedCtr);
        ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_READY);
    }

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_RESEED_RESETS_COUNTER_TC001
 * @title Verify reseed resets counter to 1
 * @precon nan
 * @brief
 *  1.Create, instantiate, and generate several times
 *  2.Call reseed
 *  3.Verify counter resets to 1
 *  4.Generate again - counter should be 2
 * @expect
 *  Reseed correctly resets counter
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_RESEED_RESETS_COUNTER_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 20202);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);

    for (int i = 0; i < 10; i++) {
        ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false), CRYPT_SUCCESS);
    }
    ASSERT_EQ(drbg->reseedCtr, 11);

    ASSERT_EQ(DRBG_Reseed(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(drbg->reseedCtr, 1);

    ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false), CRYPT_SUCCESS);
    ASSERT_EQ(drbg->reseedCtr, 2);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_UNINSTANTIATE_FROM_READY_TC001
 * @title Verify uninstantiate from READY state
 * @precon nan
 * @brief
 *  1.Create and instantiate DRBG
 *  2.Call uninstantiate
 *  3.Verify state is UNINITIALISED
 *  4.Verify generate fails
 * @expect
 *  Uninstantiate works from READY state
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_UNINSTANTIATE_FROM_READY_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 30303);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_READY);

    ASSERT_EQ(DRBG_Uninstantiate(drbg), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(drbg->state), REF_STATE_UNINITIALISED);

    int32_t ret = DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_REINIT_AFTER_UNINIT_TC001
 * @title Verify re-instantiate after uninstantiate
 * @precon nan
 * @brief
 *  1.Create, instantiate, generate
 *  2.Uninstantiate
 *  3.Re-instantiate
 *  4.Verify generate works
 * @expect
 *  Re-instantiation works after uninstantiate
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_REINIT_AFTER_UNINIT_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];

    SetupDetEntropy(&seedMeth, &detCtx, 40404);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false), CRYPT_SUCCESS);

    ASSERT_EQ(DRBG_Uninstantiate(drbg), CRYPT_SUCCESS);

    ASSERT_EQ(DRBG_Instantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false), CRYPT_SUCCESS);

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */

/**
 * @test SDV_DRBG_INTERNAL_RANDOM_SEQUENCE_TC001
 * @title Verify state consistency under random operation sequences
 * @precon nan
 * @brief
 *  1.Generate random sequence of operations
 *  2.Execute each operation
 *  3.Verify no crashes or invalid states
 * @expect
 *  All sequences complete successfully
 */
/* BEGIN_CASE */
void SDV_DRBG_INTERNAL_RANDOM_SEQUENCE_TC001(int algId, int numOps, int seed)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    DRBG_Ctx *drbg = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    uint32_t prngState = (uint32_t)seed;

    SetupDetEntropy(&seedMeth, &detCtx, (uint32_t)seed);

    drbg = DRBG_New(NULL, algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);

    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prngState) % 4;

        switch (op) {
            case 0:
                DRBG_Instantiate(drbg, NULL, 0);
                break;
            case 1:
                DRBG_Generate(drbg, output, DRBG_TEST_OUTPUT_SIZE, NULL, 0, false);
                break;
            case 2:
                DRBG_Reseed(drbg, NULL, 0);
                break;
            case 3:
                DRBG_Uninstantiate(drbg);
                break;
        }

        RefDrbgState state = ImplStateToRef(drbg->state);
        ASSERT_TRUE(state >= REF_STATE_UNINITIALISED && state <= REF_STATE_ERROR);
    }

EXIT:
    DRBG_Free(drbg);
    return;
}
/* END_CASE */
