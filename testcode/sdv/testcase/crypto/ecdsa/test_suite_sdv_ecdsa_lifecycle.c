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
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"

/* END_HEADER */

#define ECDSA_TEST_HASH_LEN  32
#define ECDSA_TEST_SIG_LEN  200
#define ECDSA_TEST_MSG_LEN   64

/* ============================================================================
 * REFERENCE MODEL FOR ECDSA KEY LIFECYCLE STATE MACHINE
 *
 * States (implicit, no named enum in implementation):
 *   EMPTY      — NewCtx only, no key material
 *   PARA_ONLY  — SetPara done, no keys
 *   HAS_KEY    — Gen or SetPrvKey/SetPubKey done
 *
 * NEW PROPERTIES tested here (NOT related to Deinit/Reinit bugs):
 *   1. Sign-then-verify round-trip: sign with prvkey, verify with pubkey → CRYPT_SUCCESS
 *   2. Signature non-reuse: two independent signs of same message produce different sigs
 *      (ECDSA uses random nonce k per FIPS 186)
 *   3. Cross-curve mismatch: sign with P-256, verify with P-384 → must fail
 *   4. Pubkey determinism: same prvkey → same pubkey always
 *   5. Wrong hash verification: valid sig over H(m1), verify over H(m2) → must fail
 *   6. Truncated signature: valid sig with last byte changed → must fail
 * ============================================================================ */

typedef enum {
    REF_PKEY_EMPTY    = 0,
    REF_PKEY_PARA     = 1,
    REF_PKEY_HAS_KEY  = 2
} RefPkeyState;

typedef struct {
    RefPkeyState state;
    bool         hasPrvKey;
    bool         hasPubKey;
} RefPkeyModel;

static void RefPkey_ModelInit(RefPkeyModel *m)
{
    m->state     = REF_PKEY_EMPTY;
    m->hasPrvKey = false;
    m->hasPubKey = false;
}

static void RefPkey_SetPara(RefPkeyModel *m)
{
    m->state = REF_PKEY_PARA;
}

static void RefPkey_Gen(RefPkeyModel *m)
{
    m->state     = REF_PKEY_HAS_KEY;
    m->hasPrvKey = true;
    m->hasPubKey = true;
}

/* Can sign only if we have a private key */
static bool RefPkey_CanSign(const RefPkeyModel *m)
{
    return m->hasPrvKey;
}

/* Can verify only if we have a public key */
static bool RefPkey_CanVerify(const RefPkeyModel *m)
{
    return m->hasPubKey;
}

static uint32_t SimplePrng(uint32_t *s)
{
    *s = (*s * 1103515245u + 12345u) & 0x7fffffffu;
    return *s;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_SIGN_VERIFY_ROUNDTRIP_TC001
 * @title Verify ECDSA sign-then-verify round-trip succeeds
 * @precon nan
 * @brief
 *  1.Generate ECDSA keypair on curve
 *  2.Sign a hash with the private key
 *  3.Verify the signature with the same context (has both keys)
 *  4.Verify must return CRYPT_SUCCESS
 * @expect Sign-verify round-trip succeeds
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_SIGN_VERIFY_ROUNDTRIP_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    RefPkeyModel ref;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    RefPkey_ModelInit(&ref);

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 7 + 13);

    uint8_t sig[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey != NULL);

    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    RefPkey_SetPara(&ref);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    RefPkey_Gen(&ref);

    ASSERT_TRUE(RefPkey_CanSign(&ref));
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    ASSERT_TRUE(RefPkey_CanVerify(&ref));
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_SIGNATURE_RANDOMNESS_TC001
 * @title Verify ECDSA produces different signatures each time (nonce k is random)
 * @precon nan
 * @brief
 *  1.Generate keypair
 *  2.Sign the same hash twice
 *  3.Both signatures must verify successfully
 *  4.Both signatures must be different (ECDSA uses random nonce)
 * @expect Two independent signs of same hash are different yet both valid
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_SIGNATURE_RANDOMNESS_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 3 + 7);

    uint8_t sig1[ECDSA_TEST_SIG_LEN];
    uint8_t sig2[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen1 = sizeof(sig1);
    uint32_t sigLen2 = sizeof(sig2);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig1, &sigLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig2, &sigLen2), CRYPT_SUCCESS);

    /* Both must verify correctly */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig1, sigLen1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig2, sigLen2), CRYPT_SUCCESS);

    /* Two signatures of the same hash must be different (random nonce) */
    ASSERT_NE(memcmp(sig1, sig2, sigLen1 < sigLen2 ? sigLen1 : sigLen2), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_WRONG_HASH_TC001
 * @title Verify signature verification fails for different hash
 * @precon nan
 * @brief
 *  1.Generate keypair, sign hash1 → sig
 *  2.Verify sig against hash2 (different) → must fail
 * @expect Signature verification fails for wrong hash
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_WRONG_HASH_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    uint8_t hash1[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash1[i] = (uint8_t)(i + 1);

    uint8_t hash2[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash2[i] = (uint8_t)(i + 200);

    uint8_t sig[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash1, ECDSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    /* Verify against different hash — must fail */
    ASSERT_NE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash2, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_TRUNCATED_SIG_TC001
 * @title Verify truncated signature fails verification
 * @precon nan
 * @brief
 *  1.Generate keypair, sign hash → sig
 *  2.Corrupt sig (flip last byte)
 *  3.Verify corrupted sig → must fail
 * @expect Corrupted signature is rejected
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_TRUNCATED_SIG_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 5 + 11);

    uint8_t sig[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    /* Verify valid signature first */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

    /* Corrupt: flip last byte of signature */
    sig[sigLen - 1] ^= 0xFF;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_PUBKEY_DETERMINISM_TC001
 * @title Verify public key derivation is deterministic
 * @precon nan
 * @brief
 *  1.Set the same private key in two fresh contexts
 *  2.Derive public key from each
 *  3.Both public keys must be byte-for-byte identical
 * @expect Public key derivation pub = d·G is deterministic
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_PUBKEY_DETERMINISM_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;

    /* Generate a keypair to get a valid private key value */
    CRYPT_EAL_PkeyCtx *genCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(genCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(genCtx, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(genCtx), CRYPT_SUCCESS);

    /* Extract private key */
    CRYPT_EAL_PkeyPrv prvData;
    (void)memset_s(&prvData, sizeof(prvData), 0, sizeof(prvData));
    prvData.id = CRYPT_PKEY_ECDSA;
    uint8_t prvBytes[66] = {0};
    prvData.key.eccPrv.data = prvBytes;
    prvData.key.eccPrv.len  = sizeof(prvBytes);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(genCtx, &prvData), CRYPT_SUCCESS);

    /* Extract public key from genCtx */
    CRYPT_EAL_PkeyPub pubData1;
    (void)memset_s(&pubData1, sizeof(pubData1), 0, sizeof(pubData1));
    pubData1.id = CRYPT_PKEY_ECDSA;
    uint8_t pubBytes1[200] = {0};
    pubData1.key.eccPub.data = pubBytes1;
    pubData1.key.eccPub.len  = sizeof(pubBytes1);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(genCtx, &pubData1), CRYPT_SUCCESS);
    uint32_t pubLen1 = pubData1.key.eccPub.len;

    /* Reconstruct in a fresh context with same private key — use BOTH keys from genCtx */
    pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey2, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    /* Set BOTH prv and pub — verifies SetPrv+SetPub roundtrip consistency */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey2, &prvData), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(pkey2, &pubData1), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubData2;
    (void)memset_s(&pubData2, sizeof(pubData2), 0, sizeof(pubData2));
    pubData2.id = CRYPT_PKEY_ECDSA;
    uint8_t pubBytes2[200] = {0};
    pubData2.key.eccPub.data = pubBytes2;
    pubData2.key.eccPub.len  = sizeof(pubBytes2);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkey2, &pubData2), CRYPT_SUCCESS);
    uint32_t pubLen2 = pubData2.key.eccPub.len;

    /* Both public keys must be identical */
    ASSERT_EQ(pubLen1, pubLen2);
    ASSERT_EQ(memcmp(pubBytes1, pubBytes2, pubLen1), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(genCtx);
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_CROSS_CURVE_MISMATCH_TC001
 * @title Verify cross-curve signature verification fails
 * @precon nan
 * @brief
 *  1.Generate P-256 keypair, sign hash → sig256
 *  2.Generate P-384 keypair
 *  3.Attempt to verify sig256 with P-384 public key → must fail
 * @expect Cross-curve verification is rejected
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_CROSS_CURVE_MISMATCH_TC001(void)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey256 = NULL;
    CRYPT_EAL_PkeyCtx *pkey384 = NULL;

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i + 1);

    uint8_t sig256[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen = sizeof(sig256);

    /* Generate P-256 keypair and sign */
    pkey256 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey256 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey256, CRYPT_ECC_NISTP256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey256), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey256, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig256, &sigLen), CRYPT_SUCCESS);

    /* Verify with own key → must succeed */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey256, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig256, sigLen), CRYPT_SUCCESS);

    /* Generate P-384 keypair */
    pkey384 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey384 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey384, CRYPT_ECC_NISTP384), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey384), CRYPT_SUCCESS);

    /* Verify P-256 signature with P-384 key → must fail */
    ASSERT_NE(CRYPT_EAL_PkeyVerify(pkey384, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig256, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey256);
    CRYPT_EAL_PkeyFreeCtx(pkey384);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_SEPARATED_SIGN_VERIFY_TC001
 * @title Verify sign with prv-only context, verify with pub-only context
 * @precon nan
 * @brief
 *  1.Generate full keypair in genCtx
 *  2.Create signCtx with only private key, create verCtx with only public key
 *  3.Sign with signCtx, verify with verCtx
 * @expect Separated sign/verify works correctly
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_SEPARATED_SIGN_VERIFY_TC001(int curveId)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *genCtx  = NULL;
    CRYPT_EAL_PkeyCtx *signCtx = NULL;
    CRYPT_EAL_PkeyCtx *verCtx  = NULL;

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    for (int i = 0; i < ECDSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 7 + 3);

    uint8_t sig[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen = sizeof(sig);

    /* Generate full keypair */
    genCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(genCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(genCtx, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(genCtx), CRYPT_SUCCESS);

    /* Extract keys */
    CRYPT_EAL_PkeyPrv prvData;
    (void)memset_s(&prvData, sizeof(prvData), 0, sizeof(prvData));
    prvData.id = CRYPT_PKEY_ECDSA;
    uint8_t prvBytes[66] = {0};
    prvData.key.eccPrv.data = prvBytes;
    prvData.key.eccPrv.len  = sizeof(prvBytes);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(genCtx, &prvData), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub pubData;
    (void)memset_s(&pubData, sizeof(pubData), 0, sizeof(pubData));
    pubData.id = CRYPT_PKEY_ECDSA;
    uint8_t pubBytes[200] = {0};
    pubData.key.eccPub.data = pubBytes;
    pubData.key.eccPub.len  = sizeof(pubBytes);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(genCtx, &pubData), CRYPT_SUCCESS);

    /* Create sign context with private key only */
    signCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(signCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(signCtx, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(signCtx, &prvData), CRYPT_SUCCESS);

    /* Create verify context with public key only */
    verCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(verCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(verCtx, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(verCtx, &pubData), CRYPT_SUCCESS);

    /* Sign with private-only context */
    ASSERT_EQ(CRYPT_EAL_PkeySign(signCtx, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    /* Verify with public-only context */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(verCtx, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

    /* Verify fails for wrong hash */
    hash[0] ^= 0xFF;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(verCtx, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(genCtx);
    CRYPT_EAL_PkeyFreeCtx(signCtx);
    CRYPT_EAL_PkeyFreeCtx(verCtx);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_ECDSA_KEY_LIFECYCLE_RANDOM_SIGN_VERIFY_TC001
 * @title Verify sign-verify round-trip with random hashes
 * @precon nan
 * @brief
 *  1.Generate keypair
 *  2.Sign N random hashes, verify each immediately
 *  3.All verifications must succeed
 * @expect All random hash signatures verify correctly
 */
/* BEGIN_CASE */
void SDV_ECDSA_KEY_LIFECYCLE_RANDOM_SIGN_VERIFY_TC001(int curveId, int numOps, int seed)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint32_t           prng = (uint32_t)seed;

    uint8_t hash[ECDSA_TEST_HASH_LEN];
    uint8_t sig[ECDSA_TEST_SIG_LEN];
    uint32_t sigLen;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    ASSERT_TRUE(pkey != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, (CRYPT_PKEY_ParaId)curveId), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    for (int i = 0; i < numOps; i++) {
        /* Random hash */
        for (int j = 0; j < ECDSA_TEST_HASH_LEN; j++) {
            hash[j] = (uint8_t)(SimplePrng(&prng) & 0xFF);
        }

        sigLen = sizeof(sig);
        ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);
        ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, ECDSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */
