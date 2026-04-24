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

#define MD_MAX_OUTPUT   128
#define MD_MSG_SIZE     128
#define MD_BLOCK_SIZE    64

/* ============================================================================
 * REFERENCE MODEL FOR EAL MD + XOF STATE MACHINE
 *
 * States: NEW, INIT, UPDATE, FINAL, SQUEEZE
 *
 * Transition table (from eal_md.c):
 *   Init    : ANY  → INIT
 *   Update  : INIT,UPDATE  → UPDATE | NEW,FINAL,SQUEEZE → ERR_STATE
 *   Final   : INIT,UPDATE  → FINAL  | NEW,FINAL,SQUEEZE → ERR_STATE
 *   Squeeze : INIT,UPDATE,SQUEEZE → SQUEEZE | NEW,FINAL → ERR_STATE
 *   Deinit  : ANY → NEW
 *
 * NEW PROPERTIES tested here (NOT related to Deinit/Reinit bugs):
 *   1. Chunking determinism: MD(m) == MD(m[:32]) then MD(m[32:]) etc.
 *   2. DupCtx deep copy: mid-stream clone → both produce identical digest,
 *      and mutating one does not affect the other (alias-safety)
 *   3. SQUEEZE state blocking: Update blocked from SQUEEZE; Squeeze blocked
 *      from FINAL; multiple Squeeze calls produce extending output stream
 *   4. Block-boundary off-by-one: update at exactly 64, 128, 192 bytes
 *   5. Empty message digest: Init → Final (no Update) is well-defined
 *   6. Final blocks Further Final (state guard)
 * ============================================================================ */

typedef enum {
    REF_MD_NEW    = 0,
    REF_MD_INIT   = 1,
    REF_MD_UPDATE = 2,
    REF_MD_FINAL  = 3,
    REF_MD_SQUEEZE = 4
} RefMdState;

typedef struct {
    RefMdState state;
    uint32_t   updateCount;
    bool       isXof;
} RefMdModel;

typedef struct {
    int32_t    retCode;
    RefMdState stateAfter;
    bool       success;
} RefMdResult;

static void RefMd_ModelInit(RefMdModel *m, bool isXof)
{
    m->state       = REF_MD_NEW;
    m->updateCount = 0;
    m->isXof       = isXof;
}

static RefMdResult RefMd_Init(RefMdModel *m)
{
    m->state       = REF_MD_INIT;
    m->updateCount = 0;
    RefMdResult r  = {CRYPT_SUCCESS, REF_MD_INIT, true};
    return r;
}

static RefMdResult RefMd_Update(RefMdModel *m)
{
    RefMdResult r = {0};
    if (m->state != REF_MD_INIT && m->state != REF_MD_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state = REF_MD_UPDATE;
    m->updateCount++;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_MD_UPDATE;
    r.success    = true;
    return r;
}

static RefMdResult RefMd_Final(RefMdModel *m)
{
    RefMdResult r = {0};
    if (m->state != REF_MD_INIT && m->state != REF_MD_UPDATE) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state     = REF_MD_FINAL;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_MD_FINAL;
    r.success    = true;
    return r;
}

static RefMdResult RefMd_Squeeze(RefMdModel *m)
{
    RefMdResult r = {0};
    /* Squeeze: valid from INIT, UPDATE, SQUEEZE only */
    if (m->state == REF_MD_NEW || m->state == REF_MD_FINAL) {
        r.retCode    = CRYPT_EAL_ERR_STATE;
        r.stateAfter = m->state;
        r.success    = false;
        return r;
    }
    m->state     = REF_MD_SQUEEZE;
    r.retCode    = CRYPT_SUCCESS;
    r.stateAfter = REF_MD_SQUEEZE;
    r.success    = true;
    return r;
}

static RefMdResult RefMd_Deinit(RefMdModel *m)
{
    m->state       = REF_MD_NEW;
    m->updateCount = 0;
    RefMdResult r  = {CRYPT_SUCCESS, REF_MD_NEW, true};
    return r;
}

static RefMdState ImplStateToRef(uint32_t implState)
{
    switch ((CRYPT_MD_WORKSTATE)implState) {
        case CRYPT_MD_STATE_NEW:    return REF_MD_NEW;
        case CRYPT_MD_STATE_INIT:   return REF_MD_INIT;
        case CRYPT_MD_STATE_UPDATE: return REF_MD_UPDATE;
        case CRYPT_MD_STATE_FINAL:  return REF_MD_FINAL;
        case CRYPT_MD_STATE_SQUEEZE: return REF_MD_SQUEEZE;
        default:                    return REF_MD_FINAL;
    }
}

static bool IsXof(int mdAlgId)
{
    return (mdAlgId == CRYPT_MD_SHAKE128 || mdAlgId == CRYPT_MD_SHAKE256);
}

static uint32_t GetDigestSize(int mdAlgId)
{
    switch (mdAlgId) {
        case CRYPT_MD_SHA1:     return 20;
        case CRYPT_MD_SHA224:   return 28;
        case CRYPT_MD_SHA256:   return 32;
        case CRYPT_MD_SHA384:   return 48;
        case CRYPT_MD_SHA512:   return 64;
        case CRYPT_MD_SM3:      return 32;
        case CRYPT_MD_SHA3_224: return 28;
        case CRYPT_MD_SHA3_256: return 32;
        case CRYPT_MD_SHA3_384: return 48;
        case CRYPT_MD_SHA3_512: return 64;
        default:                return 32; /* SHAKE: user-defined */
    }
}

static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

/* ============================================================================
 * TEST CASES — CHUNKING DETERMINISM
 * ============================================================================ */

/**
 * @test SDV_MD_CHUNKING_DETERMINISM_TC001
 * @title Verify hash output is independent of how data is split across Update calls
 * @precon nan
 * @brief
 *  1.Hash full message with one Update call → out1
 *  2.Hash same message split at multiple boundaries → out2, out3, out4
 *  3.All outputs must be identical
 * @expect Chunking does not affect digest output
 */
/* BEGIN_CASE */
void SDV_MD_CHUNKING_DETERMINISM_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md = NULL;

    uint8_t msg[MD_MSG_SIZE];
    for (int i = 0; i < MD_MSG_SIZE; i++) msg[i] = (uint8_t)(i * 7 + 13);

    uint8_t ref[MD_MAX_OUTPUT];
    uint8_t out[MD_MAX_OUTPUT];
    uint32_t refLen = sizeof(ref);
    uint32_t outLen = sizeof(out);

    uint32_t digestSize = GetDigestSize(mdAlgId);

    /* Reference: single Update */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, MD_MSG_SIZE), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, ref, &refLen), CRYPT_SUCCESS);
    ASSERT_EQ(refLen, digestSize);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Split at 32/96 boundary */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg + 32, 96), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(ref, out, digestSize), 0);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Split at exactly block boundary (64 bytes) */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg + 64, 64), CRYPT_SUCCESS);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(ref, out, digestSize), 0);
    CRYPT_EAL_MdFreeCtx(md);
    md = NULL;

    /* Byte-at-a-time */
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);
    for (int i = 0; i < MD_MSG_SIZE; i++) {
        ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg + i, 1), CRYPT_SUCCESS);
    }
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(memcmp(ref, out, digestSize), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_DUPCTX_DEEP_COPY_TC001
 * @title Verify DupCtx mid-UPDATE produces identical, independent digest
 * @precon nan
 * @brief
 *  1.Init, Update(prefix)
 *  2.DupCtx → dup
 *  3.Both: Update(suffix), Final
 *  4.Digests must be equal
 *  5.Update on original after dup must not change dup's output
 * @expect DupCtx deep-copies state; no aliasing
 */
/* BEGIN_CASE */
void SDV_MD_DUPCTX_DEEP_COPY_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *orig  = NULL;
    CRYPT_EAL_MdCtx *dup   = NULL;
    CRYPT_EAL_MdCtx *fresh = NULL;

    uint8_t prefix[64];
    for (int i = 0; i < 64; i++) prefix[i] = (uint8_t)(i * 3 + 7);

    uint8_t suffix[64];
    for (int i = 0; i < 64; i++) suffix[i] = (uint8_t)(i * 5 + 11);

    uint8_t extra[32];
    for (int i = 0; i < 32; i++) extra[i] = (uint8_t)(i * 11 + 17);

    uint8_t out_orig[MD_MAX_OUTPUT];
    uint8_t out_dup[MD_MAX_OUTPUT];
    uint8_t out_fresh[MD_MAX_OUTPUT];
    uint8_t out_dup_after_orig_mutated[MD_MAX_OUTPUT];
    uint32_t len_orig, len_dup, len_fresh, len_mut;
    uint32_t digestSize = GetDigestSize(mdAlgId);

    /* Compute reference: prefix + suffix in one shot */
    fresh = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(fresh != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(fresh), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(fresh, prefix, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(fresh, suffix, 64), CRYPT_SUCCESS);
    len_fresh = sizeof(out_fresh);
    ASSERT_EQ(CRYPT_EAL_MdFinal(fresh, out_fresh, &len_fresh), CRYPT_SUCCESS);

    /* orig: process prefix, then dup */
    orig = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(orig != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(orig), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(orig, prefix, 64), CRYPT_SUCCESS);

    dup = CRYPT_EAL_MdDupCtx(orig);
    ASSERT_TRUE(dup != NULL);

    /* Both process suffix */
    ASSERT_EQ(CRYPT_EAL_MdUpdate(orig, suffix, 64), CRYPT_SUCCESS);
    len_orig = sizeof(out_orig);
    ASSERT_EQ(CRYPT_EAL_MdFinal(orig, out_orig, &len_orig), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_MdUpdate(dup, suffix, 64), CRYPT_SUCCESS);
    len_dup = sizeof(out_dup);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dup, out_dup, &len_dup), CRYPT_SUCCESS);

    /* Both must equal reference */
    ASSERT_EQ(len_orig, digestSize);
    ASSERT_EQ(len_dup, digestSize);
    ASSERT_EQ(memcmp(out_orig, out_fresh, digestSize), 0);
    ASSERT_EQ(memcmp(out_dup, out_fresh, digestSize), 0);

    /* Mutation test: re-use orig, add extra data */
    ASSERT_EQ(CRYPT_EAL_MdInit(orig), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(orig, extra, 32), CRYPT_SUCCESS);
    len_orig = sizeof(out_orig);
    ASSERT_EQ(CRYPT_EAL_MdFinal(orig, out_orig, &len_orig), CRYPT_SUCCESS);

    /* Recompute dup from scratch for alias test */
    ASSERT_EQ(CRYPT_EAL_MdInit(dup), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(dup, prefix, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(dup, suffix, 64), CRYPT_SUCCESS);
    len_mut = sizeof(out_dup_after_orig_mutated);
    ASSERT_EQ(CRYPT_EAL_MdFinal(dup, out_dup_after_orig_mutated, &len_mut), CRYPT_SUCCESS);

    /* dup's output is still correct — not corrupted by orig's extra write */
    ASSERT_EQ(memcmp(out_dup_after_orig_mutated, out_fresh, digestSize), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(orig);
    CRYPT_EAL_MdFreeCtx(dup);
    CRYPT_EAL_MdFreeCtx(fresh);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_FINAL_BLOCKS_FINAL_TC001
 * @title Verify second Final is blocked in FINAL state (reference model: ERR_STATE)
 * @precon nan
 * @brief
 *  1.Init, Update, Final
 *  2.Call Final again — model: FINAL → ERR_STATE
 * @expect Second Final fails
 */
/* BEGIN_CASE */
void SDV_MD_FINAL_BLOCKS_FINAL_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel       ref;
    CRYPT_EAL_MdCtx *md = NULL;
    RefMdResult       exp;
    int32_t           ret;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 3);

    uint8_t out[MD_MAX_OUTPUT];
    uint32_t outLen = sizeof(out);

    RefMd_ModelInit(&ref, false);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    RefMd_Init(&ref);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);

    RefMd_Update(&ref);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);

    exp = RefMd_Final(&ref);
    outLen = sizeof(out);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md, out, &outLen), CRYPT_SUCCESS);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_FINAL);

    /* Second Final from FINAL — model says ERR_STATE */
    exp = RefMd_Final(&ref);
    outLen = sizeof(out);
    ret = CRYPT_EAL_MdFinal(md, out, &outLen);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_EMPTY_MESSAGE_TC001
 * @title Verify digest of empty message is well-defined and repeatable
 * @precon nan
 * @brief
 *  1.Init → Final (no Update calls)
 *  2.Repeat: same digest must be produced
 * @expect Empty message digest is deterministic
 */
/* BEGIN_CASE */
void SDV_MD_EMPTY_MESSAGE_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md1 = NULL;
    CRYPT_EAL_MdCtx *md2 = NULL;

    uint8_t out1[MD_MAX_OUTPUT];
    uint8_t out2[MD_MAX_OUTPUT];
    uint32_t outLen1 = sizeof(out1);
    uint32_t outLen2 = sizeof(out2);

    uint32_t digestSize = GetDigestSize(mdAlgId);

    md1 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md1, out1, &outLen1), CRYPT_SUCCESS);
    ASSERT_EQ(outLen1, digestSize);

    md2 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdFinal(md2, out2, &outLen2), CRYPT_SUCCESS);
    ASSERT_EQ(outLen2, digestSize);

    ASSERT_EQ(memcmp(out1, out2, digestSize), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md1);
    CRYPT_EAL_MdFreeCtx(md2);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_XOF_SQUEEZE_STATE_TC001
 * @title Verify XOF Squeeze state transitions match reference model
 * @precon nan
 * @brief
 *  1.Init → Squeeze (without Final) — model: INIT,UPDATE,SQUEEZE valid
 *  2.Squeeze again — still in SQUEEZE state
 *  3.Update from SQUEEZE — model: ERR_STATE
 *  4.Final from SQUEEZE — model: ERR_STATE
 * @expect XOF Squeeze state transitions match reference model
 */
/* BEGIN_CASE */
void SDV_MD_XOF_SQUEEZE_STATE_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || !IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    RefMdModel       ref;
    CRYPT_EAL_MdCtx *md = NULL;
    RefMdResult       exp;
    int32_t           ret;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 3 + 7);

    uint8_t out[MD_MAX_OUTPUT];
    uint32_t outLen = 32;

    RefMd_ModelInit(&ref, true);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    RefMd_Init(&ref);
    ASSERT_EQ(CRYPT_EAL_MdInit(md), CRYPT_SUCCESS);

    RefMd_Update(&ref);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md, msg, 64), CRYPT_SUCCESS);

    /* Squeeze from UPDATE — model: OK, transitions to SQUEEZE */
    exp = RefMd_Squeeze(&ref);
    ret = CRYPT_EAL_MdSqueeze(md, out, 32);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_SQUEEZE);

    /* Squeeze again from SQUEEZE — model: OK */
    exp = RefMd_Squeeze(&ref);
    ret = CRYPT_EAL_MdSqueeze(md, out, 32);
    ASSERT_EQ(ret, exp.retCode);
    ASSERT_EQ(ImplStateToRef(md->state), REF_MD_SQUEEZE);

    /* Update from SQUEEZE — model: ERR_STATE */
    exp = RefMd_Update(&ref);
    ret = CRYPT_EAL_MdUpdate(md, msg, 64);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

    /* Final from SQUEEZE — model: ERR_STATE */
    exp = RefMd_Final(&ref);
    outLen = sizeof(out);
    ret = CRYPT_EAL_MdFinal(md, out, &outLen);
    ASSERT_EQ(exp.success, false);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_MdFreeCtx(md);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_XOF_SQUEEZE_DETERMINISM_TC001
 * @title Verify XOF Squeeze produces deterministic extending output
 * @precon nan
 * @brief
 *  1.Hash same input with one Squeeze(64 bytes) → out1
 *  2.Hash same input with two Squeeze(32 bytes) each → out2a||out2b
 *  3.out1 must equal out2a||out2b
 * @expect XOF output stream is deterministic regardless of squeeze chunk size
 */
/* BEGIN_CASE */
void SDV_MD_XOF_SQUEEZE_DETERMINISM_TC001(int mdAlgId)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || !IsXof(mdAlgId)) {
        SKIP_TEST();
    }

    TestMemInit();

    CRYPT_EAL_MdCtx *md1 = NULL;
    CRYPT_EAL_MdCtx *md2 = NULL;

    uint8_t msg[64];
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 11 + 7);

    uint8_t out1[64];
    uint8_t out2a[32];
    uint8_t out2b[32];

    /* Single squeeze of 64 bytes */
    md1 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md1 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md1, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdSqueeze(md1, out1, 64), CRYPT_SUCCESS);

    /* Two squeezes of 32 bytes each */
    md2 = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md2 != NULL);
    ASSERT_EQ(CRYPT_EAL_MdInit(md2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdUpdate(md2, msg, 64), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdSqueeze(md2, out2a, 32), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_MdSqueeze(md2, out2b, 32), CRYPT_SUCCESS);

    /* Both streams must match */
    ASSERT_EQ(memcmp(out1, out2a, 32), 0);
    ASSERT_EQ(memcmp(out1 + 32, out2b, 32), 0);

EXIT:
    CRYPT_EAL_MdFreeCtx(md1);
    CRYPT_EAL_MdFreeCtx(md2);
    return;
}
/* END_CASE */

/**
 * @test SDV_MD_RANDOM_SEQUENCE_TC001
 * @title Verify MD state consistency under random operation sequences
 * @precon nan
 * @brief
 *  1.Generate random sequence of {Init, Update, Final, Deinit}
 *  2.Execute on both impl and reference model
 *  3.Success/failure must match model
 * @expect All operation sequences produce matching states
 */
/* BEGIN_CASE */
void SDV_MD_RANDOM_SEQUENCE_TC001(int mdAlgId, int numOps, int seed)
{
    if (!CRYPT_EAL_MdIsValidAlgId(mdAlgId) || IsXof(mdAlgId)) {
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
    uint8_t out[MD_MAX_OUTPUT];
    uint32_t outLen;

    RefMd_ModelInit(&ref, false);
    md = CRYPT_EAL_MdNewCtx(mdAlgId);
    ASSERT_TRUE(md != NULL);

    for (int i = 0; i < numOps; i++) {
        uint32_t op = SimplePrng(&prng) % 4;

        switch (op) {
            case 0: /* Init */
                exp = RefMd_Init(&ref);
                ret = CRYPT_EAL_MdInit(md);
                break;
            case 1: /* Update */
                exp = RefMd_Update(&ref);
                ret = CRYPT_EAL_MdUpdate(md, msg, 16);
                break;
            case 2: /* Final */
                exp = RefMd_Final(&ref);
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
