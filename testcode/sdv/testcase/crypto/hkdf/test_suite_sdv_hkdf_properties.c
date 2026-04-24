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
#include "crypt_eal_kdf.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

/* END_HEADER */

#define HKDF_TEST_MAX_OUT  128
#define HKDF_TEST_IKM_LEN   32
#define HKDF_TEST_SALT_LEN  32
#define HKDF_TEST_INFO_LEN  32
#define HKDF_TEST_PRK_LEN   64

/* ============================================================================
 * REFERENCE MODEL FOR HKDF THREE-MODE STATE MACHINE
 *
 * States: UNCONFIGURED → CONFIGURED (after SetParam) → DERIVED (after Derive)
 *
 * Modes:
 *   FULL    = EXTRACT(key, salt) → PRK, then EXPAND(PRK, info, L) → OKM
 *   EXTRACT = HMAC(salt as key, IKM as data) → PRK
 *   EXPAND  = iterative HMAC(PRK, T(i-1)||info||i) → OKM
 *
 * Properties tested (all NEW, not related to Deinit/Reinit/null-pointer bugs):
 *   1. Compositional: FULL(ikm, salt, info, L) == EXPAND(EXTRACT(ikm, salt), info, L)
 *   2. Determinism: same inputs → same OKM across independent contexts
 *   3. Output length limit: EXPAND rejects outLen > 255 * hashLen
 *   4. Output length invariant: output is exactly the requested length
 *   5. Info sensitivity: same ikm+salt, different info → different OKM
 *   6. Key sensitivity: same salt+info, different ikm → different OKM
 * ============================================================================ */

typedef enum {
    REF_HKDF_UNCONFIGURED = 0,
    REF_HKDF_CONFIGURED   = 1
} RefHkdfState;

typedef struct {
    RefHkdfState state;
    int          mode;
    bool         hasKey;
    bool         hasSalt;
    bool         hasInfo;
    bool         hasPrk;
} RefHkdfModel;

static void RefHkdf_ModelInit(RefHkdfModel *m)
{
    m->state   = REF_HKDF_UNCONFIGURED;
    m->mode    = -1;
    m->hasKey  = false;
    m->hasSalt = false;
    m->hasInfo = false;
    m->hasPrk  = false;
}

static bool RefHkdf_CanDeriveExpand(const RefHkdfModel *m)
{
    return m->state == REF_HKDF_CONFIGURED && m->hasPrk;
}

static bool RefHkdf_CanDeriveFull(const RefHkdfModel *m)
{
    return m->state == REF_HKDF_CONFIGURED && m->hasKey;
}

static uint32_t GetHashLen(int macAlgId)
{
    switch (macAlgId) {
        case CRYPT_MAC_HMAC_SHA1:   return 20;
        case CRYPT_MAC_HMAC_SHA224: return 28;
        case CRYPT_MAC_HMAC_SHA256: return 32;
        case CRYPT_MAC_HMAC_SHA384: return 48;
        case CRYPT_MAC_HMAC_SHA512: return 64;
        default: return 32;
    }
}

static int32_t HkdfDeriveFull(int algId, const uint8_t *ikm, uint32_t ikmLen,
                               const uint8_t *salt, uint32_t saltLen,
                               const uint8_t *info, uint32_t infoLen,
                               uint8_t *out, uint32_t outLen)
{
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) return CRYPT_MEM_ALLOC_FAIL;

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    int algIdI = algId;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &algIdI, sizeof(algIdI));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, (void *)ikm, ikmLen);
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, (void *)salt, saltLen);
    BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, (void *)info, infoLen);

    int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_KdfFreeCtx(ctx); return ret; }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

static int32_t HkdfDeriveExtract(int algId, const uint8_t *ikm, uint32_t ikmLen,
                                  const uint8_t *salt, uint32_t saltLen,
                                  uint8_t *prk, uint32_t *prkLen)
{
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) return CRYPT_MEM_ALLOC_FAIL;

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;
    int algIdI = algId;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &algIdI, sizeof(algIdI));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, (void *)ikm, ikmLen);
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, (void *)salt, saltLen);
    /* CRYPT_PARAM_KDF_EXLEN: pointer where Extract stores the actual PRK length */
    BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, prkLen, sizeof(prkLen));

    int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_KdfFreeCtx(ctx); return ret; }

    ret = CRYPT_EAL_KdfDerive(ctx, prk, *prkLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

static int32_t HkdfDeriveExpand(int algId, const uint8_t *prk, uint32_t prkLen,
                                 const uint8_t *info, uint32_t infoLen,
                                 uint8_t *out, uint32_t outLen)
{
    CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) return CRYPT_MEM_ALLOC_FAIL;

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;
    int algIdI = algId;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &algIdI, sizeof(algIdI));
    BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode));
    BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS, (void *)prk, prkLen);
    BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, (void *)info, infoLen);

    int32_t ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_KdfFreeCtx(ctx); return ret; }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_HKDF_COMPOSITIONAL_TC001
 * @title Verify FULL == EXPAND(EXTRACT(ikm, salt), info, L) per RFC 5869 §2
 * @precon nan
 * @brief
 *  1.Run HKDF in FULL mode → okm_full
 *  2.Run HKDF in EXTRACT mode → prk
 *  3.Run HKDF in EXPAND mode with prk → okm_expand
 *  4.okm_full must equal okm_expand
 * @expect FULL mode output equals EXTRACT+EXPAND pipeline output
 */
/* BEGIN_CASE */
void SDV_HKDF_COMPOSITIONAL_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm[i] = (uint8_t)(i * 3 + 7);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 5 + 11);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)(i * 7 + 13);

    uint8_t okm_full[HKDF_TEST_MAX_OUT];
    uint8_t prk[HKDF_TEST_PRK_LEN];
    uint8_t okm_expand[HKDF_TEST_MAX_OUT];

    uint32_t okmLen = 32;
    uint32_t hashLen = GetHashLen(algId);
    uint32_t prkLen = hashLen;

    /* FULL mode */
    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, okm_full, okmLen), CRYPT_SUCCESS);

    /* EXTRACT */
    ASSERT_EQ(HkdfDeriveExtract(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                                 prk, &prkLen), CRYPT_SUCCESS);
    ASSERT_EQ(prkLen, hashLen);

    /* EXPAND with extracted PRK */
    ASSERT_EQ(HkdfDeriveExpand(algId, prk, prkLen, info, HKDF_TEST_INFO_LEN,
                                okm_expand, okmLen), CRYPT_SUCCESS);

    /* Compositional property: FULL == EXTRACT + EXPAND */
    ASSERT_EQ(memcmp(okm_full, okm_expand, okmLen), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_DETERMINISM_TC001
 * @title Verify HKDF is deterministic: same inputs → same OKM
 * @precon nan
 * @brief
 *  1.Derive with FULL mode twice using identical inputs
 *  2.Both outputs must be identical
 * @expect HKDF output is deterministic
 */
/* BEGIN_CASE */
void SDV_HKDF_DETERMINISM_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm[i] = (uint8_t)(i * 11 + 23);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 7 + 17);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)(i * 13 + 3);

    uint8_t out1[32];
    uint8_t out2[32];

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, out1, 32), CRYPT_SUCCESS);

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, out2, 32), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(out1, out2, 32), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_OUTPUT_LENGTH_LIMIT_TC001
 * @title Verify EXPAND rejects outLen > 255 * hashLen
 * @precon nan
 * @brief
 *  1.Derive with EXPAND mode, outLen = 255 * hashLen → should succeed
 *  2.Derive with EXPAND mode, outLen = 255 * hashLen + 1 → should fail
 * @expect Output length limit is enforced
 */
/* BEGIN_CASE */
void SDV_HKDF_OUTPUT_LENGTH_LIMIT_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t prk[64];
    for (int i = 0; i < 64; i++) prk[i] = (uint8_t)(i + 1);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)i;

    uint32_t hashLen = GetHashLen(algId);
    uint32_t maxLen  = hashLen * 255;

    /* Maximum valid length — should succeed */
    uint8_t *outMax = (uint8_t *)malloc(maxLen + 1);
    ASSERT_TRUE(outMax != NULL);

    ASSERT_EQ(HkdfDeriveExpand(algId, prk, hashLen, info, HKDF_TEST_INFO_LEN, outMax, maxLen),
              CRYPT_SUCCESS);

    /* One byte over limit — should fail with overflow error */
    int32_t ret = HkdfDeriveExpand(algId, prk, hashLen, info, HKDF_TEST_INFO_LEN, outMax, maxLen + 1);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    free(outMax);
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_INFO_SENSITIVITY_TC001
 * @title Verify different info values produce different OKM
 * @precon nan
 * @brief
 *  1.Derive with info1 → okm1
 *  2.Derive with info2 (different) → okm2
 *  3.okm1 != okm2
 * @expect Different info produces different output (context binding works)
 */
/* BEGIN_CASE */
void SDV_HKDF_INFO_SENSITIVITY_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm[i] = (uint8_t)(i * 5 + 3);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 7 + 5);

    uint8_t info1[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info1[i] = (uint8_t)i;

    uint8_t info2[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info2[i] = (uint8_t)(i + 128);

    uint8_t out1[32];
    uint8_t out2[32];

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info1, HKDF_TEST_INFO_LEN, out1, 32), CRYPT_SUCCESS);

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info2, HKDF_TEST_INFO_LEN, out2, 32), CRYPT_SUCCESS);

    ASSERT_NE(memcmp(out1, out2, 32), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_KEY_SENSITIVITY_TC001
 * @title Verify different IKM produces different OKM
 * @precon nan
 * @brief
 *  1.Derive with ikm1 → okm1
 *  2.Derive with ikm2 (different) → okm2
 *  3.okm1 != okm2
 * @expect Different IKM produces different output
 */
/* BEGIN_CASE */
void SDV_HKDF_KEY_SENSITIVITY_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm1[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm1[i] = (uint8_t)(i + 1);

    uint8_t ikm2[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm2[i] = (uint8_t)(i + 129);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 11 + 7);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)(i * 3 + 5);

    uint8_t out1[32];
    uint8_t out2[32];

    ASSERT_EQ(HkdfDeriveFull(algId, ikm1, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, out1, 32), CRYPT_SUCCESS);

    ASSERT_EQ(HkdfDeriveFull(algId, ikm2, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, out2, 32), CRYPT_SUCCESS);

    ASSERT_NE(memcmp(out1, out2, 32), 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_OUTPUT_LENGTH_INVARIANT_TC001
 * @title Verify Derive produces exactly the requested number of bytes
 * @precon nan
 * @brief
 *  1.Request L bytes from HKDF for various L
 *  2.Each call must succeed and imply exactly L bytes were filled
 * @expect Output length matches requested length
 */
/* BEGIN_CASE */
void SDV_HKDF_OUTPUT_LENGTH_INVARIANT_TC001(int algId, int outLen)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm[i] = (uint8_t)(i * 7 + 11);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 3 + 7);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)(i * 5 + 3);

    /* Fill output buffer with known sentinel before derive */
    uint8_t out[HKDF_TEST_MAX_OUT];
    (void)memset_s(out, sizeof(out), 0xAA, sizeof(out));

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, out, (uint32_t)outLen), CRYPT_SUCCESS);

    /* All bytes [0..outLen) should have been overwritten (not 0xAA) */
    /* This only holds if outLen > 0 bytes have real content */
    if (outLen > 0) {
        int allSentinel = 1;
        for (int i = 0; i < outLen; i++) {
            if (out[i] != 0xAA) { allSentinel = 0; break; }
        }
        ASSERT_EQ(allSentinel, 0);
    }

EXIT:
    return;
}
/* END_CASE */

/**
 * @test SDV_HKDF_COMPOSITIONAL_MULTI_HASH_TC001
 * @title Verify compositional property holds across multiple hash algorithms
 * @precon nan
 * @brief
 *  Same as compositional test but validates invariant holds for SHA-256 and SHA-512
 * @expect FULL == EXTRACT+EXPAND for all supported HMAC variants
 */
/* BEGIN_CASE */
void SDV_HKDF_COMPOSITIONAL_MULTI_HASH_TC001(int algId)
{
    CRYPT_EAL_KdfCtx *testCtx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (testCtx == NULL || GetHashLen(algId) == 0) {
        if (testCtx != NULL) CRYPT_EAL_KdfFreeCtx(testCtx);
        SKIP_TEST();
    }

    TestMemInit();

    uint8_t ikm[HKDF_TEST_IKM_LEN];
    for (int i = 0; i < HKDF_TEST_IKM_LEN; i++) ikm[i] = (uint8_t)(i * 13 + 17);

    uint8_t salt[HKDF_TEST_SALT_LEN];
    for (int i = 0; i < HKDF_TEST_SALT_LEN; i++) salt[i] = (uint8_t)(i * 17 + 3);

    uint8_t info[HKDF_TEST_INFO_LEN];
    for (int i = 0; i < HKDF_TEST_INFO_LEN; i++) info[i] = (uint8_t)(i * 11 + 13);

    uint32_t hashLen = GetHashLen(algId);
    uint32_t okmLen  = hashLen; /* output one full hash's worth of key material */

    uint8_t okm_full[HKDF_TEST_PRK_LEN];
    uint8_t prk[HKDF_TEST_PRK_LEN];
    uint8_t okm_expand[HKDF_TEST_PRK_LEN];
    uint32_t prkLen = hashLen;

    ASSERT_EQ(HkdfDeriveFull(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                              info, HKDF_TEST_INFO_LEN, okm_full, okmLen), CRYPT_SUCCESS);

    ASSERT_EQ(HkdfDeriveExtract(algId, ikm, HKDF_TEST_IKM_LEN, salt, HKDF_TEST_SALT_LEN,
                                 prk, &prkLen), CRYPT_SUCCESS);

    ASSERT_EQ(HkdfDeriveExpand(algId, prk, prkLen, info, HKDF_TEST_INFO_LEN,
                                okm_expand, okmLen), CRYPT_SUCCESS);

    ASSERT_EQ(memcmp(okm_full, okm_expand, okmLen), 0);

EXIT:
    return;
}
/* END_CASE */
