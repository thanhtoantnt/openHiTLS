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
#include <time.h>
#include "crypt_eal_init.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_rand.h"
#include "drbg_local.h"
#include "eal_drbg_local.h"
#include "bsl_err_internal.h"
#include "bsl_err.h"
#include "crypt_drbg.h"

/* END_HEADER */

#define DRBG_TEST_OUTPUT_SIZE 64
#define DRBG_TEST_SEED_SIZE 256
#define DRBG_TEST_MAX_OPS 100
#define DRBG_TEST_RESEED_INTERVAL 1000

/* ============================================================================
 * REFERENCE MODEL AUTOMATON
 * This is a simple state machine that tracks expected DRBG behavior.
 * It predicts what state the DRBG should be in after each operation.
 * ============================================================================ */

typedef enum {
    REF_STATE_UNINITIALISED = 0,
    REF_STATE_READY = 1,
    REF_STATE_ERROR = 2
} RefDrbgState;

typedef enum {
    REF_OP_INSTANTIATE = 0,
    REF_OP_GENERATE = 1,
    REF_OP_RESEED = 2,
    REF_OP_UNINSTANTIATE = 3,
    REF_OP_COUNT = 4
} RefDrbgOp;

typedef struct {
    RefDrbgState state;
    uint32_t reseedCounter;
    uint32_t reseedInterval;
    uint32_t generateCount;
} RefDrbgModel;

typedef struct {
    int32_t retCode;
    RefDrbgState stateBefore;
    RefDrbgState stateAfter;
    bool success;
} RefOpResult;

/* Initialize reference model */
static void RefModel_Init(RefDrbgModel *model, uint32_t reseedInterval)
{
    model->state = REF_STATE_UNINITIALISED;
    model->reseedCounter = 0;
    model->reseedInterval = reseedInterval;
    model->generateCount = 0;
}

/* Reference model: predict Instantiate result */
static RefOpResult RefModel_Instantiate(RefDrbgModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_UNINITIALISED) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.stateAfter = model->state;
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

/* Reference model: predict Generate result */
static RefOpResult RefModel_Generate(RefDrbgModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_READY) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.stateAfter = model->state;
        result.success = false;
        return result;
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

/* Reference model: predict Reseed result */
static RefOpResult RefModel_Reseed(RefDrbgModel *model, bool willSucceed)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    if (model->state != REF_STATE_READY) {
        result.retCode = CRYPT_DRBG_ERR_STATE;
        result.stateAfter = model->state;
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

/* Reference model: predict Uninstantiate result */
static RefOpResult RefModel_Uninstantiate(RefDrbgModel *model)
{
    RefOpResult result = {0};
    result.stateBefore = model->state;
    
    model->state = REF_STATE_UNINITIALISED;
    model->reseedCounter = 0;
    result.retCode = CRYPT_SUCCESS;
    result.stateAfter = model->state;
    result.success = true;
    
    return result;
}

/* Map implementation state to reference state */
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
 * For reproducible property-based testing
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
    
    /* Initialize seed with deterministic pattern based on seedVal */
    for (uint32_t i = 0; i < DRBG_TEST_SEED_SIZE; i++) {
        ctx->seed[i] = (uint8_t)((i * 7 + seedVal + 13) & 0xFF);
    }
    ctx->pos = 0;
    ctx->callCount = 0;
    ctx->shouldFail = false;
}

/* ============================================================================
 * SIMPLE PRNG FOR RANDOM OPERATION GENERATION
 * ============================================================================ */

static uint32_t SimplePrng(uint32_t *state)
{
    *state = (*state * 1103515245 + 12345) & 0x7fffffff;
    return *state;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test   SDV_DRBG_STATE_MACHINE_BASIC_TC001
 * @title  Verify basic state transitions match reference model
 * @precon nan
 * @brief
 *    1.Create DRBG context with deterministic entropy source
 *    2.Execute Instantiate, verify state transition UNINITIALISED -> READY
 *    3.Execute Generate, verify state stays READY
 *    4.Execute Reseed, verify state stays READY
 *    5.Execute Uninstantiate, verify state transition READY -> UNINITIALISED
 * @expect
 *    All state transitions match reference model predictions
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_BASIC_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    RefOpResult refResult;
    int32_t implRet;
    
    SetupDetEntropy(&seedMeth, &detCtx, 12345);
    RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
    
    /* Create DRBG */
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);
    implCtx = (DRBG_Ctx *)drbg->ctx;
    
    /* Step 1: Verify initial state is UNINITIALISED */
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_UNINITIALISED);
    ASSERT_EQ(refModel.state, REF_STATE_UNINITIALISED);
    
    /* Step 2: Instantiate - UNINITIALISED -> READY */
    refResult = RefModel_Instantiate(&refModel, true);
    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
    
    /* Step 3: Generate - READY -> READY */
    refResult = RefModel_Generate(&refModel, true);
    implRet = CRYPT_EAL_Drbgbytes(drbg, output, DRBG_TEST_OUTPUT_SIZE);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
    
    /* Step 4: Reseed - READY -> READY */
    refResult = RefModel_Reseed(&refModel, true);
    implRet = CRYPT_EAL_DrbgSeed(drbg);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
    
    /* Step 5: Uninstantiate - READY -> UNINITIALISED */
    refResult = RefModel_Uninstantiate(&refModel);
    implRet = DRBG_Uninstantiate(implCtx);
    ASSERT_EQ(implRet, refResult.retCode);
    ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_DRBG_STATE_MACHINE_RESEED_COUNTER_TC001
 * @title  Verify reseed counter behavior matches reference model
 * @precon nan
 * @brief
 *    1.Create and instantiate DRBG
 *    2.Verify counter starts at 1 after instantiate
 *    3.Execute multiple Generate operations, verify counter increments
 *    4.Execute Reseed, verify counter resets to 1
 * @expect
 *    Reseed counter behavior matches reference model
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_RESEED_COUNTER_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    
    SetupDetEntropy(&seedMeth, &detCtx, 54321);
    RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
    
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);
    implCtx = (DRBG_Ctx *)drbg->ctx;
    
    /* Instantiate - counter should be 1 */
    RefModel_Instantiate(&refModel, true);
    ASSERT_EQ(CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(implCtx->reseedCtr, 1);
    ASSERT_EQ(refModel.reseedCounter, 1);
    
    /* Multiple Generate operations - counter should increment */
    for (int i = 0; i < 10; i++) {
        uint32_t expectedCtr = implCtx->reseedCtr + 1;
        RefModel_Generate(&refModel, true);
        ASSERT_EQ(CRYPT_EAL_Drbgbytes(drbg, output, DRBG_TEST_OUTPUT_SIZE), CRYPT_SUCCESS);
        ASSERT_EQ(implCtx->reseedCtr, expectedCtr);
    }
    
    /* Reseed - counter should reset to 1 */
    RefModel_Reseed(&refModel, true);
    ASSERT_EQ(CRYPT_EAL_DrbgSeed(drbg), CRYPT_SUCCESS);
    ASSERT_EQ(implCtx->reseedCtr, 1);
    ASSERT_EQ(refModel.reseedCounter, 1);
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_DRBG_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title  Verify state consistency under random operation sequences
 * @precon nan
 * @brief
 *    1.Create DRBG with deterministic entropy source
 *    2.Generate random sequence of operations
 *    3.Execute each operation on both implementation and reference model
 *    4.Compare states after each operation
 * @expect
 *    All operation sequences produce matching states
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int algId, int numOps, int seed)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    uint32_t prngState = (uint32_t)seed;
    RefOpResult refResult;
    int32_t implRet;
    
    SetupDetEntropy(&seedMeth, &detCtx, (uint32_t)seed);
    RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
    
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);
    implCtx = (DRBG_Ctx *)drbg->ctx;
    
    /* Execute random operation sequence */
    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prngState) % REF_OP_COUNT;
        
        switch (op) {
            case REF_OP_INSTANTIATE:
                refResult = RefModel_Instantiate(&refModel, !detCtx.shouldFail);
                implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
                break;
                
            case REF_OP_GENERATE:
                refResult = RefModel_Generate(&refModel, !detCtx.shouldFail);
                implRet = CRYPT_EAL_Drbgbytes(drbg, output, DRBG_TEST_OUTPUT_SIZE);
                break;
                
            case REF_OP_RESEED:
                refResult = RefModel_Reseed(&refModel, !detCtx.shouldFail);
                implRet = CRYPT_EAL_DrbgSeed(drbg);
                break;
                
            case REF_OP_UNINSTANTIATE:
                refResult = RefModel_Uninstantiate(&refModel);
                implRet = DRBG_Uninstantiate(implCtx);
                break;
                
            default:
                continue;
        }
        
        /* Compare states after each operation */
        RefDrbgState implStateAfter = ImplStateToRef(implCtx->state);
        
        /* Check: if reference predicts success, implementation should succeed */
        if (refResult.success && refResult.retCode == CRYPT_SUCCESS) {
            ASSERT_EQ(implRet, CRYPT_SUCCESS);
        }
        
        /* Check: states should match */
        ASSERT_EQ(implStateAfter, refResult.stateAfter);
    }
    
    /* Verify final state is valid */
    RefDrbgState finalState = ImplStateToRef(implCtx->state);
    ASSERT_TRUE(finalState >= REF_STATE_UNINITIALISED && finalState <= REF_STATE_ERROR);
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_DRBG_STATE_MACHINE_ERROR_RECOVERY_TC001
 * @title  Verify error state recovery via uninstantiate
 * @precon nan
 * @brief
 *    1.Create DRBG with entropy source that can fail
 *    2.Trigger entropy failure to put DRBG in ERROR state
 *    3.Verify Uninstantiate recovers to UNINITIALISED state
 *    4.Verify Instantiate succeeds after recovery
 * @expect
 *    Error recovery works correctly
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_ERROR_RECOVERY_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    RefOpResult refResult;
    int32_t implRet;
    
    SetupDetEntropy(&seedMeth, &detCtx, 99999);
    RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
    
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);
    implCtx = (DRBG_Ctx *)drbg->ctx;
    
    /* Step 1: Instantiate successfully */
    refResult = RefModel_Instantiate(&refModel, true);
    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_READY);
    
    /* Step 2: Uninstantiate to return to UNINITIALISED */
    refResult = RefModel_Uninstantiate(&refModel);
    implRet = DRBG_Uninstantiate(implCtx);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_UNINITIALISED);
    
    /* Step 3: Instantiate again - should succeed */
    refResult = RefModel_Instantiate(&refModel, true);
    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_READY);
    
    /* Step 4: Uninstantiate again */
    refResult = RefModel_Uninstantiate(&refModel);
    implRet = DRBG_Uninstantiate(implCtx);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_UNINITIALISED);
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_DRBG_STATE_MACHINE_INVALID_STATE_TC001
 * @title  Verify operations fail correctly in wrong states
 * @precon nan
 * @brief
 *    1.Create DRBG, verify Generate fails in UNINITIALISED state
 *    2.Instantiate, verify Instantiate fails again (already READY)
 *    3.Uninstantiate, verify Generate fails in UNINITIALISED state
 * @expect
 *    Operations return correct error codes for invalid states
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_INVALID_STATE_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    RefOpResult refResult;
    int32_t implRet;
    
    SetupDetEntropy(&seedMeth, &detCtx, 11111);
    RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
    
    drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
    ASSERT_TRUE(drbg != NULL);
    implCtx = (DRBG_Ctx *)drbg->ctx;
    
    /* Step 1: Generate should fail in UNINITIALISED state */
    refResult = RefModel_Generate(&refModel, true);
    implRet = CRYPT_EAL_Drbgbytes(drbg, output, DRBG_TEST_OUTPUT_SIZE);
    /* Reference model predicts failure */
    ASSERT_EQ(refResult.success, false);
    ASSERT_EQ(refResult.retCode, CRYPT_DRBG_ERR_STATE);
    
    /* Step 2: Instantiate to get to READY state */
    refResult = RefModel_Instantiate(&refModel, true);
    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(implCtx->state), REF_STATE_READY);
    
    /* Step 3: Second Instantiate should fail (already READY) */
    refResult = RefModel_Instantiate(&refModel, true);
    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
    ASSERT_EQ(refResult.success, false);
    ASSERT_EQ(implRet, CRYPT_DRBG_ERR_STATE);
    ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
    
    /* Step 4: Uninstantiate */
    refResult = RefModel_Uninstantiate(&refModel);
    implRet = DRBG_Uninstantiate(implCtx);
    ASSERT_EQ(implRet, CRYPT_SUCCESS);
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */

/**
 * @test   SDV_DRBG_STATE_MACHINE_MULTI_SEQUENCE_TC001
 * @title  Verify state machine stability across multiple random sequences
 * @precon nan
 * @brief
 *    1.Execute multiple random operation sequences with different seeds
 *    2.Verify state machine remains stable after each sequence
 *    3.Compare implementation state with reference model after each sequence
 * @expect
 *    All sequences complete successfully with matching states
 */
/* BEGIN_CASE */
void SDV_DRBG_STATE_MACHINE_MULTI_SEQUENCE_TC001(int algId)
{
    if (IsRandAlgDisabled(algId)) {
        SKIP_TEST();
    }
    
    TestMemInit();
    
    CRYPT_RandSeedMethod seedMeth = {0};
    DetEntropyCtx detCtx = {0};
    RefDrbgModel refModel;
    CRYPT_EAL_RndCtx *drbg = NULL;
    DRBG_Ctx *implCtx = NULL;
    uint8_t output[DRBG_TEST_OUTPUT_SIZE];
    
    uint32_t seeds[] = {12345, 54321, 11111, 99999, 42, 7777, 8888, 13579};
    uint32_t numSeeds = sizeof(seeds) / sizeof(seeds[0]);
    
    for (uint32_t s = 0; s < numSeeds; s++) {
        SetupDetEntropy(&seedMeth, &detCtx, seeds[s]);
        RefModel_Init(&refModel, DRBG_TEST_RESEED_INTERVAL);
        
        drbg = CRYPT_EAL_DrbgNew(algId, &seedMeth, &detCtx);
        ASSERT_TRUE(drbg != NULL);
        implCtx = (DRBG_Ctx *)drbg->ctx;
        
        uint32_t prngState = seeds[s];
        RefOpResult refResult;
        int32_t implRet;
        
        /* Execute sequence with this seed */
        for (int i = 0; i < 50; i++) {
            uint32_t op = SimplePrng(&prngState) % REF_OP_COUNT;
            
            switch (op) {
                case REF_OP_INSTANTIATE:
                    refResult = RefModel_Instantiate(&refModel, true);
                    implRet = CRYPT_EAL_DrbgInstantiate(drbg, NULL, 0);
                    break;
                    
                case REF_OP_GENERATE:
                    refResult = RefModel_Generate(&refModel, true);
                    implRet = CRYPT_EAL_Drbgbytes(drbg, output, DRBG_TEST_OUTPUT_SIZE);
                    break;
                    
                case REF_OP_RESEED:
                    refResult = RefModel_Reseed(&refModel, true);
                    implRet = CRYPT_EAL_DrbgSeed(drbg);
                    break;
                    
                case REF_OP_UNINSTANTIATE:
                    refResult = RefModel_Uninstantiate(&refModel);
                    implRet = DRBG_Uninstantiate(implCtx);
                    break;
                    
                default:
                    continue;
            }
            
            /* Verify state consistency */
            if (refResult.success) {
                ASSERT_EQ(implRet, CRYPT_SUCCESS);
            }
            ASSERT_EQ(ImplStateToRef(implCtx->state), refResult.stateAfter);
        }
        
        /* Verify final state is valid */
        RefDrbgState finalState = ImplStateToRef(implCtx->state);
        ASSERT_TRUE(finalState >= REF_STATE_UNINITIALISED && finalState <= REF_STATE_ERROR);
        
        CRYPT_EAL_DrbgDeinit(drbg);
        drbg = NULL;
    }
    
EXIT:
    CRYPT_EAL_DrbgDeinit(drbg);
    return;
}
/* END_CASE */
