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
#include "crypt_eal_md.h"
#include "eal_md_local.h"

/* END_HEADER */

#define MD_TEST_MAX_OUTPUT_SIZE 64
#define MD_TEST_MSG_SIZE        128
#define MD_TEST_MAX_OPS         100

/* ============================================================================
 * REFERENCE MODEL FOR EAL MD STATE MACHINE
 *
 * States: NEW, INIT, UPDATE, FINAL
 *         (SQUEEZE is only for SHAKE variants — not tested here)
 *
 * Transition table (from eal_md.c):
 *
 *   Init   : ANY  → INIT
 *   Update : INIT, UPDATE  → UPDATE   | NEW, FINAL, SQUEEZE → ERR_STATE
 *   Final  : INIT, UPDATE  → FINAL    | NEW, FINAL, SQUEEZE → ERR_STATE
 *   Deinit : ANY  → NEW
 *
 * ============================================================================ */

typedef enum {
    REF_MD_NEW = 0,
    REF_MD_INIT,
    REF_MD_UPDATE,
    REF_MD_FINAL
} RefMdState;

typedef struct {
    RefMdState state;
    uint32_t   updateCount;
} RefMdModel;

typedef struct {
    int32_t    retCode;
    RefMdState stateAfter;
    bool       success;
} RefMdResult;

static void RefMd_ModelInit(RefMdModel *m)
{
    m->state       = REF_MD_NEW;
    m->updateCount = 0;
}

/* Init: valid from any state → INIT */
static RefMdResult RefMd_Init(RefMdModel *m, bool willSucceed)
{
    RefMdResult r = {0};
    if (willSucceed) {
        m->state       = REF_MD_INIT;
        m->updateCount = 0;
        r.retCode      = CRYPT_SUCCESS;
        r.success      = true;
    } else {
        r.retCode  = CRYPT_NULL_INPUT;
        r.success  = false;
    }
    r.stateAfter = m->state;
    return r;
}

/* Update: INIT,UPDATE → UPDATE; otherwise ERR_STATE */
static RefMdResult RefMd_Update(RefMdModel *m, bool willSucceed)
{
    RefMdResult r = {0};
    if (m->state != REF_MD_INIT && m->state != REF_MD_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    if (willSucceed) {
        m->state = REF_MD_UPDATE;
        m->updateCount++;
        r.retCode = CRYPT_SUCCESS;
        r.success = true;
    } else {
        r.retCode = CRYPT_NULL_INPUT;
        r.success = false;
    }
    r.stateAfter = m->state;
    return r;
}

/* Final: INIT,UPDATE → FINAL; otherwise ERR_STATE */
static RefMdResult RefMd_Final(RefMdModel *m, bool willSucceed)
{
    RefMdResult r = {0};
    if (m->state != REF_MD_INIT && m->state != REF_MD_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    if (willSucceed) {
        m->state  = REF_MD_FINAL;
        r.retCode = CRYPT_SUCCESS;
        r.success = true;
    } else {
        r.retCode = CRYPT_NULL_INPUT;
        r.success = false;
    }
    r.stateAfter = m->state;
    return r;
}

/* Deinit: ANY → NEW */
static RefMdResult RefMd_Deinit(RefMdModel *m)
{
    m->state       = REF_MD_NEW;
    m->updateCount = 0;
    RefMdResult r  = {CRYPT_SUCCESS, REF_MD_NEW, true};
    return r;
}

/* Map EAL state to reference state */
static RefMdState ImplStateToRef(uint32_t implState)
{
    switch ((CRYPT_MD_WORKSTATE)implState) {
        case CRYPT_MD_STATE_NEW:    return REF_MD_NEW;
        case CRYPT_MD_STATE_INIT:   return REF_MD_INIT;
        case CRYPT_MD_STATE_UPDATE: return REF_MD_UPDATE;
        case CRYPT_MD_STATE_FINAL:  return REF_MD_FINAL;
        default:                    return REF_MD_FINAL;
    }
}

/* Simple PRNG for sequence generation */
static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_MD_STATE_MACHINE_BASIC_TC001
 * @title Verify EAL MD basic state transitions match reference model
 * @precon nan
 * @brief
 *  1.NewCtx → state must be NEW
 *  2.Init  → NEW  → INIT
 *  3.Update → INIT → UPDATE
 *  4.Final  → UPDATE → FINAL
 *  5.Deinit → FINAL → NEW
 * @expect All transitions match reference model
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_BASIC_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel         ref;
    CRYPT_EAL_MdCtx   *md = NULL;
    RefMdResult        exp;
    int32_t            ret;

    uint8_t msg[MD_TEST_MSG_SIZE];
    for (int i = 0; i < MD_TEST_MSG_SIZE; i++) msg[i] = (uint8_t)i;

    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefMd_ModelInit(&ref);

    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);

    exp = RefMd_Init(&ref, true);
    ret = CRYPT_EAL_MdInit(md);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

    exp = RefMd_Update(&ref, true);
    ret = CRYPT_EAL_MdUpdate(md, msg, MD_TEST_MSG_SIZE);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

    exp = RefMd_Final(&ref, true);
    ret = CRYPT_EAL_MdFinal(md, out, &outLen);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

    exp = RefMd_Deinit(&ref);
    ret = CRYPT_EAL_MdDeinit(md);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_INVALID_TC001
 * @title Verify operations fail correctly in wrong states (reference model check)
 * @precon nan
 * @brief
 *  1.Update from NEW → model predicts ERR_STATE
 *  2.Final from NEW  → model predicts ERR_STATE
 *  3.Init, then Final from INIT (no data) → should succeed
 *  4.Update from FINAL → model predicts ERR_STATE
 * @expect All error states match reference model predictions
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_INVALID_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel         ref;
    CRYPT_EAL_MdCtx   *md = NULL;
    RefMdResult        exp;
    int32_t            ret;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 3);

    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefMd_ModelInit(&ref);

    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    /* Update from NEW — must fail */
    exp = RefMd_Update(&ref, true);
    ret = CRYPT_EAL_MdUpdate(md, msg, 64);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* Final from NEW — must fail */
    exp = RefMd_Final(&ref, true);
    ret = CRYPT_EAL_MdFinal(md, out, &outLen);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* Init then Final (no Update) — must succeed */
    exp = RefMd_Init(&ref, true);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

    exp = RefMd_Final(&ref, true);
    ret = CRYPT_EAL_MdFinal(md, out, &outLen);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_FINAL);

    /* Update from FINAL — must fail */
    exp = RefMd_Update(&ref, true);
    ret = CRYPT_EAL_MdUpdate(md, msg, 64);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_DEINIT_RESETS_TC001
 * @title Verify Deinit always resets to NEW regardless of current state
 * @precon nan
 * @brief
 *  Test Deinit from: NEW, INIT, UPDATE, FINAL
 *  After each, verify state == NEW and Init succeeds
 * @expect Deinit always transitions to NEW
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_DEINIT_RESETS_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md = NULL;
    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;
    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    /* Deinit from NEW */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Deinit from INIT */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_INIT);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Deinit from UPDATE */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_UPDATE);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Deinit from FINAL */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_FINAL);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_REINIT_TC001
 * @title Verify MdInit from FINAL state acts as re-init (transitions to INIT)
 * @precon nan
 * @brief
 *  1.Init, Update(msg), Final → out1
 *  2.Init again from FINAL state
 *  3.Update(msg), Final → out2
 *  4.Verify out1 == out2 (same message, Init resets cleanly)
 * @expect Init from FINAL resets correctly; same input produces same output
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_REINIT_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel ref;
    CRYPT_EAL_MdCtx *md = NULL;
    RefMdResult exp;
    int32_t ret;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 13);

    uint8_t out1[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out2[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    RefMd_ModelInit(&ref);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    /* First computation */
    exp = RefMd_Init(&ref, true);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);

    exp = RefMd_Update(&ref, true);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), exp.retCode);

    exp = RefMd_Final(&ref, true);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out1, &outLen1), exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_FINAL);

    /* Re-Init from FINAL (reference model: Init is valid from any state) */
    exp = RefMd_Init(&ref, true);
    ret = CRYPT_EAL_MdInit(md);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_INIT);

    /* Second computation with same message */
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out2, &outLen2), CRYPT_SUCCESS);

    /* Determinism: same input must produce same output */
    ASSERT_EQ(outLen1, outLen2);
    ASSERT_EQ(memcmp(out1, out2, outLen1), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_DETERMINISM_TC001
 * @title Verify MD output is deterministic: same input always gives same digest
 * @precon nan
 * @brief
 *  1.Create two contexts, same algorithm
 *  2.Init, Update(same msg), Final on both
 *  3.Outputs must be equal
 * @expect Digest is deterministic
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_DETERMINISM_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md1 = NULL;
    CRYPT_EAL_MdCtx *md2 = NULL;

    uint8_t msg[128];
    for (int i = 0; i < 128; i++) msg[i] = (uint8_t)(i * 5 + 11);

    uint8_t out1[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out2[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    md1 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md1, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md1, out1, &outLen1), CRYPT_SUCCESS);

    md2 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md2, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md2, out2, &outLen2), CRYPT_SUCCESS);

    ASSERT_EQ(outLen1, outLen2);
    ASSERT_EQ(memcmp(out1, out2, outLen1), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md1);
    CRYPT_EAL_MdFreeCtx(md2);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_CHAINING_TC001
 * @title Verify Update chaining: splitting message produces same digest as single Update
 * @precon nan
 * @brief
 *  1.Compute digest with one Update(full_msg)
 *  2.Compute digest with Update(part1) + Update(part2) + Update(part3)
 *  3.Verify outputs are equal
 * @expect MD(m) == MD after Update(m[0:32]) + Update(m[32:64]) + Update(m[64:128])
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_CHAINING_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md1 = NULL;
    CRYPT_EAL_MdCtx *md2 = NULL;

    uint8_t msg[128];
    for (int i = 0; i < 128; i++) msg[i] = (uint8_t)(i * 11 + 17);

    uint8_t out1[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out2[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    md1 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md1, msg, 128), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md1, out1, &outLen1), CRYPT_SUCCESS);

    md2 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md2, msg,       32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md2, msg + 32,  32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md2, msg + 64,  64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md2, out2, &outLen2), CRYPT_SUCCESS);

    ASSERT_EQ(outLen1, outLen2);
    ASSERT_EQ(memcmp(out1, out2, outLen1), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md1);
    CRYPT_EAL_MdFreeCtx(md2);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_DUPCTX_TC001
 * @title Verify DupCtx produces a fully independent copy
 * @precon nan
 * @brief
 *  1.Init, Update(msg1)
 *  2.DupCtx
 *  3.Original: Final → out1
 *  4.Dup: Final → out2
 *  5.out1 == out2 (same state at dup time)
 *  6.Dup: Init, Update(msg2), Final → out3
 *  7.Fresh context: Init, Update(msg2), Final → out4
 *  8.out3 == out4 (dup supports re-use)
 * @expect DupCtx produces identical and independent context
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_DUPCTX_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md    = NULL;
    CRYPT_EAL_MdCtx *dup   = NULL;
    CRYPT_EAL_MdCtx *fresh = NULL;

    uint8_t msg1[64];
    for (int i = 0; i < 64; i++) msg1[i] = (uint8_t)(i * 3);

    uint8_t msg2[64];
    for (int i = 0; i < 64; i++) msg2[i] = (uint8_t)(i * 7 + 5);

    uint8_t out1[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out2[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out3[MD_TEST_MAX_OUTPUT_SIZE];
    uint8_t out4[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t len1 = sizeof(out1), len2 = sizeof(out2);
    uint32_t len3 = sizeof(out3), len4 = sizeof(out4);

    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg1, 64), CRYPT_SUCCESS);

    dup = CRYPT_EAL_MdDupCtx(md);
    ASSERT_TRUE(dup != NULL);

    /* Both contexts at same point → same output */
    ASSERT_EQ(CRYPT_EAL_MdFinal(md,  out1, &len1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dup, out2, &len2), CRYPT_SUCCESS);
    ASSERT_EQ(len1, len2);
    ASSERT_EQ(memcmp(out1, out2, len1), 0);

    /* Dup re-used with different message */
    ASSERT_EQ(CRYPT_EAL_MdInit(dup), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(dup, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dup, out3, &len3), CRYPT_SUCCESS);

    fresh = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(fresh), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(fresh, msg2, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(fresh, out4, &len4), CRYPT_SUCCESS);

    ASSERT_EQ(len3, len4);
    ASSERT_EQ(memcmp(out3, out4, len3), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    CRYPT_EAL_MdFreeCtx(dup);
    CRYPT_EAL_MdFreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_DEINIT_BLOCKS_UPDATE_TC001
 * @title Verify Update fails after Deinit (state is NEW)
 * @precon nan
 * @brief
 *  1.Init, Update, Final, Deinit
 *  2.Call Update — reference model says NEW → ERR_STATE
 * @expect Update after Deinit returns ERR_STATE
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_DEINIT_BLOCKS_UPDATE_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel       ref;
    CRYPT_EAL_MdCtx *md = NULL;
    RefMdResult      exp;
    int32_t          ret;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)i;
    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefMd_ModelInit(&ref);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    RefMd_Init(&ref, true);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    RefMd_Update(&ref, true);

    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    RefMd_Final(&ref, true);

    /* Deinit → NEW */
    exp = RefMd_Deinit(&ref);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(md), exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_NEW);

    /* Update from NEW — model says ERR_STATE */
    exp = RefMd_Update(&ref, true);
    ret = CRYPT_EAL_MdUpdate(md, msg, 64);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* After deinit, Init should work */
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_INIT);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_RANDOM_SEQUENCE_TC001
 * @title Verify MD state consistency under random operation sequences
 * @precon nan
 * @brief
 *  1.Generate random sequence of {Init, Update, Final, Deinit}
 *  2.Execute each on both impl and reference model
 *  3.Compare states after every operation
 * @expect All operation sequences produce matching states
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_RANDOM_SEQUENCE_TC001(int mdAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel       ref;
    CRYPT_EAL_MdCtx *md = NULL;
    uint32_t         prng = (uint32_t)seed;
    int32_t          ret;
    RefMdResult      exp;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)((i * seed) & 0xFF);
    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    RefMd_ModelInit(&ref);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prng) % 4;

        switch (op) {
            case 0: /* Init */
                exp = RefMd_Init(&ref, true);
                ret = CRYPT_EAL_MdInit(md);
                break;
            case 1: /* Update */
                exp = RefMd_Update(&ref, true);
                ret = CRYPT_EAL_MdUpdate(md, msg, 64);
                break;
            case 2: /* Final */
                exp = RefMd_Final(&ref, true);
                outLen = sizeof(out);
                ret = CRYPT_EAL_MdFinal(md, out, &outLen);
                break;
            case 3: /* Deinit */
                exp = RefMd_Deinit(&ref);
                ret = CRYPT_EAL_MdDeinit(md);
                break;
            default:
                continue;
        }

        if (exp.success) {
            ASSERT_EQ(ret, CRYPT_SUCCESS);
        } else {
            ASSERT_NE(ret, CRYPT_SUCCESS);
        }
        ASSERT_EQ(ImplStateToRef(md->state), exp.stateAfter);
    }

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_STATE_MACHINE_NULL_PARAMS_TC001
 * @title Verify MD API handles NULL parameters correctly
 * @precon nan
 * @brief
 *  1.NULL context → all ops return CRYPT_NULL_INPUT
 *  2.Init, then Update with NULL data + nonzero len → should fail
 *  3.Final with NULL output buffer → should fail
 * @expect NULL parameters return CRYPT_NULL_INPUT or error
 */
/* BEGIN_CASE */
void SDV_MD_STATE_MACHINE_NULL_PARAMS_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md = NULL;
    uint8_t msg[64];
    uint8_t out[MD_TEST_MAX_OUTPUT_SIZE];
    uint32_t outLen = sizeof(out);

    /* NULL context */
    ASSERT_EQ(CRYPT_EAL_MdInit(NULL),                    CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(NULL, msg, 64),          CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdFinal(NULL, out, &outLen),      CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_MdDeinit(NULL),                   CRYPT_NULL_INPUT);
    ASSERT_TRUE(CRYPT_EAL_MdDupCtx(NULL) == NULL);

    /* NULL data with nonzero length */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_MdUpdate(md, NULL, 64), CRYPT_SUCCESS);

    /* NULL output buffer */
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_MdFinal(md, NULL, &outLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */
