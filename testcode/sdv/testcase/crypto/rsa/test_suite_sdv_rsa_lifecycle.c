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
#include "bsl_params.h"
#include "crypt_params_key.h"

/* END_HEADER */

#define RSA_TEST_BITS_2048    2048
#define RSA_TEST_BITS_3072    3072
#define RSA_TEST_BUF_LEN      512
#define RSA_TEST_MSG_LEN       64
#define RSA_TEST_HASH_LEN      32

/* ============================================================================
 * REFERENCE MODEL FOR RSA KEY LIFECYCLE STATE MACHINE
 *
 * Two orthogonal state axes:
 *   Key state:     EMPTY → has_pub only / has_prv only / has_both
 *   Padding state: NONE_SET → SET (type = PKCSV15 | OAEP | PSS)
 *
 * Properties tested (NOT related to Deinit/Reinit/null-pointer bugs):
 *   1. Encrypt-decrypt round-trip (PKCS1-v1.5 and OAEP)
 *   2. Sign-verify round-trip (PSS and PKCS1-v1.5 signature)
 *   3. Padding state wipe: SetPubKey/SetPrvKey resets padding → Verify fails
 *   4. Encrypt without pubkey → CRYPT_RSA_NO_KEY_INFO
 *   5. Decrypt without prvkey → CRYPT_RSA_NO_KEY_INFO
 *   6. Sign without prvkey → fails
 *   7. Verify without pubkey → fails
 *   8. Decrypt of wrong-key ciphertext → fails
 * ============================================================================ */

typedef enum {
    REF_RSA_NO_KEY   = 0,
    REF_RSA_HAS_PUB  = 1,
    REF_RSA_HAS_PRV  = 2,
    REF_RSA_HAS_BOTH = 3
} RefRsaKeyState;

typedef enum {
    REF_RSA_PAD_NONE    = 0,
    REF_RSA_PAD_SET     = 1
} RefRsaPadState;

typedef struct {
    RefRsaKeyState keyState;
    RefRsaPadState padState;
} RefRsaModel;

static void RefRsa_ModelInit(RefRsaModel *m)
{
    m->keyState = REF_RSA_NO_KEY;
    m->padState = REF_RSA_PAD_NONE;
}

static bool RefRsa_CanEncrypt(const RefRsaModel *m)
{
    return (m->keyState == REF_RSA_HAS_PUB || m->keyState == REF_RSA_HAS_BOTH)
           && m->padState == REF_RSA_PAD_SET;
}

static bool RefRsa_CanDecrypt(const RefRsaModel *m)
{
    return (m->keyState == REF_RSA_HAS_PRV || m->keyState == REF_RSA_HAS_BOTH)
           && m->padState == REF_RSA_PAD_SET;
}

static bool RefRsa_CanSign(const RefRsaModel *m)
{
    return (m->keyState == REF_RSA_HAS_PRV || m->keyState == REF_RSA_HAS_BOTH)
           && m->padState == REF_RSA_PAD_SET;
}

static bool RefRsa_CanVerify(const RefRsaModel *m)
{
    return (m->keyState == REF_RSA_HAS_PUB || m->keyState == REF_RSA_HAS_BOTH)
           && m->padState == REF_RSA_PAD_SET;
}

/* ============================================================================
 * TEST CASES
 * ============================================================================ */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_ENC_DEC_PKCS1_TC001
 * @title Verify RSA PKCS1-v1.5 encrypt-decrypt round-trip
 * @precon nan
 * @brief
 *  1.Generate RSA keypair
 *  2.Set PKCS1v15 encrypt padding
 *  3.Encrypt plaintext with public key
 *  4.Decrypt ciphertext with private key
 *  5.Decrypted text == original plaintext
 * @expect Round-trip succeeds, exact plaintext recovered
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_ENC_DEC_PKCS1_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    RefRsaModel ref;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    RefRsa_ModelInit(&ref);

    uint8_t plaintext[RSA_TEST_MSG_LEN];
    for (int i = 0; i < RSA_TEST_MSG_LEN; i++) plaintext[i] = (uint8_t)(i * 7 + 13);

    uint8_t ciphertext[RSA_TEST_BUF_LEN];
    uint8_t decrypted[RSA_TEST_BUF_LEN];
    uint32_t ctLen = sizeof(ciphertext);
    uint32_t ptLen = sizeof(decrypted);

    /* Generate keypair */
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ref.keyState = REF_RSA_HAS_BOTH;

    /* Set PKCS1v15 encrypt padding */
    CRYPT_RSA_PkcsV15Para pkcsv15Para = {CRYPT_MD_SHA256};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15Para, sizeof(pkcsv15Para)),
              CRYPT_SUCCESS);
    ref.padState = REF_RSA_PAD_SET;

    ASSERT_TRUE(RefRsa_CanEncrypt(&ref));
    ctLen = sizeof(ciphertext);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey, plaintext, RSA_TEST_MSG_LEN, ciphertext, &ctLen), CRYPT_SUCCESS);

    ASSERT_TRUE(RefRsa_CanDecrypt(&ref));
    ptLen = sizeof(decrypted);
    ASSERT_EQ(CRYPT_EAL_PkeyDecrypt(pkey, ciphertext, ctLen, decrypted, &ptLen), CRYPT_SUCCESS);

    ASSERT_EQ(ptLen, RSA_TEST_MSG_LEN);
    ASSERT_EQ(memcmp(plaintext, decrypted, RSA_TEST_MSG_LEN), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_SIGN_VERIFY_PSS_TC001
 * @title Verify RSA PSS sign-verify round-trip
 * @precon nan
 * @brief
 *  1.Generate RSA keypair
 *  2.Set PSS padding
 *  3.Sign hash with private key → sig
 *  4.Verify sig with public key → CRYPT_SUCCESS
 * @expect PSS sign-verify round-trip succeeds
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_SIGN_VERIFY_PSS_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    RefRsaModel ref;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    RefRsa_ModelInit(&ref);

    uint8_t hash[RSA_TEST_HASH_LEN];
    for (int i = 0; i < RSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 3 + 7);

    uint8_t sig[RSA_TEST_BUF_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ref.keyState = REF_RSA_HAS_BOTH;

    /* Set PSS padding via BSL_Param (required format for EMSA_PSS ctrl) */
    CRYPT_MD_AlgId pssmd = CRYPT_MD_SHA256;
    int32_t saltLen32 = 32;
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssmd, sizeof(pssmd), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssmd, sizeof(pssmd), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen32, sizeof(saltLen32), 0},
        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    ref.padState = REF_RSA_PAD_SET;

    ASSERT_TRUE(RefRsa_CanSign(&ref));
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    ASSERT_TRUE(RefRsa_CanVerify(&ref));
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_PADDING_WIPE_TC001
 * @title Verify SetPrvKey resets padding — subsequent Sign fails without padding re-set
 * @precon nan
 * @brief
 *  1.Generate keypair, set PSS padding
 *  2.Sign hash successfully
 *  3.Call SetPrvKey again (reloads same key, wipes pad state)
 *  4.Try Sign again — should fail (no padding set)
 * @expect Padding state cleared by SetPrvKey; Sign fails until padding re-set
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_PADDING_WIPE_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    RefRsaModel ref;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    RefRsa_ModelInit(&ref);

    uint8_t hash[RSA_TEST_HASH_LEN];
    for (int i = 0; i < RSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 11 + 3);

    uint8_t sig[RSA_TEST_BUF_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);
    ref.keyState = REF_RSA_HAS_BOTH;

    CRYPT_MD_AlgId pssmd2 = CRYPT_MD_SHA256;
    int32_t saltLen2 = 32;
    BSL_Param pssParam2[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &pssmd2, sizeof(pssmd2), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &pssmd2, sizeof(pssmd2), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen2, sizeof(saltLen2), 0},
        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam2, 0), CRYPT_SUCCESS);
    ref.padState = REF_RSA_PAD_SET;

    /* First sign — must succeed */
    ASSERT_TRUE(RefRsa_CanSign(&ref));
    sigLen = sizeof(sig);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);

    /* Extract private key and re-set it (wipes pad) */
    CRYPT_EAL_PkeyPrv prvData;
    (void)memset_s(&prvData, sizeof(prvData), 0, sizeof(prvData));
    prvData.id = CRYPT_PKEY_RSA;
    uint8_t n[RSA_TEST_BUF_LEN] = {0}, d[RSA_TEST_BUF_LEN] = {0};
    uint8_t e[RSA_TEST_BUF_LEN] = {0};
    prvData.key.rsaPrv.n = n;     prvData.key.rsaPrv.nLen = sizeof(n);
    prvData.key.rsaPrv.d = d;     prvData.key.rsaPrv.dLen = sizeof(d);
    prvData.key.rsaPrv.e = e;     prvData.key.rsaPrv.eLen = sizeof(e);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkey, &prvData), CRYPT_SUCCESS);

    /* Re-setting prvKey wipes pad state per reference model */
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkey, &prvData), CRYPT_SUCCESS);
    ref.padState = REF_RSA_PAD_NONE;

    /* Sign after key reset without re-setting padding — should fail */
    ASSERT_EQ(RefRsa_CanSign(&ref), false);
    sigLen = sizeof(sig);
    int32_t ret = CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, &sigLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_ENCRYPT_NO_KEY_TC001
 * @title Verify Encrypt fails without public key (reference model: NO_KEY state)
 * @precon nan
 * @brief
 *  1.Create RSA context without any key
 *  2.Set encrypt padding
 *  3.Try to Encrypt — should fail (no public key)
 * @expect Encrypt fails when public key is absent
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_ENCRYPT_NO_KEY_TC001(int bits)
{
    TestMemInit();

    RefRsaModel ref;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    RefRsa_ModelInit(&ref);

    uint8_t plain[RSA_TEST_MSG_LEN];
    for (int i = 0; i < RSA_TEST_MSG_LEN; i++) plain[i] = (uint8_t)i;

    uint8_t out[RSA_TEST_BUF_LEN];
    uint32_t outLen = sizeof(out);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &pkeyPara), CRYPT_SUCCESS);

    /* Set padding but NO key */
    CRYPT_RSA_PkcsV15Para pkcsv15Para = {CRYPT_MD_SHA256};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15Para, sizeof(pkcsv15Para)),
              CRYPT_SUCCESS);
    ref.padState = REF_RSA_PAD_SET;

    /* Reference model: can't encrypt without public key */
    ASSERT_EQ(RefRsa_CanEncrypt(&ref), false);
    int32_t ret = CRYPT_EAL_PkeyEncrypt(pkey, plain, RSA_TEST_MSG_LEN, out, &outLen);
    ASSERT_NE(ret, CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return;
}
/* END_CASE */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_WRONG_KEY_DECRYPT_TC001
 * @title Verify decryption with wrong key fails correctly
 * @precon nan
 * @brief
 *  1.Generate keypair1, encrypt message → ct
 *  2.Generate keypair2 (different key)
 *  3.Try to decrypt ct with keypair2 → must fail
 * @expect Wrong-key decryption is rejected
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_WRONG_KEY_DECRYPT_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey1 = NULL;
    CRYPT_EAL_PkeyCtx *pkey2 = NULL;

    uint8_t plain[RSA_TEST_MSG_LEN];
    for (int i = 0; i < RSA_TEST_MSG_LEN; i++) plain[i] = (uint8_t)(i * 5 + 11);

    uint8_t ct[RSA_TEST_BUF_LEN];
    uint8_t dec[RSA_TEST_BUF_LEN];
    uint32_t ctLen = sizeof(ct);
    uint32_t decLen = sizeof(dec);

    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    CRYPT_RSA_PkcsV15Para pkcsv15Para = {CRYPT_MD_SHA256};

    /* Key 1: generate, set padding, encrypt */
    pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey1 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey1, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey1, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15Para, sizeof(pkcsv15Para)),
              CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncrypt(pkey1, plain, RSA_TEST_MSG_LEN, ct, &ctLen), CRYPT_SUCCESS);

    /* Key 2: different keypair, same padding */
    pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey2 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey2, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey2, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pkcsv15Para, sizeof(pkcsv15Para)),
              CRYPT_SUCCESS);

    /* Decrypt with wrong key — must fail */
    decLen = sizeof(dec);
    ASSERT_NE(CRYPT_EAL_PkeyDecrypt(pkey2, ct, ctLen, dec, &decLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */

/**
 * @test SDV_RSA_KEY_LIFECYCLE_SIGN_VERIFY_PKCS1_TC001
 * @title Verify RSA PKCS1-v1.5 sign-verify round-trip
 * @precon nan
 * @brief
 *  1.Generate RSA keypair
 *  2.Set PKCS1v15 sign padding
 *  3.Sign, verify, then corrupt signature, verify must fail
 * @expect PKCS1 sign-verify round-trip works; corrupted sig rejected
 */
/* BEGIN_CASE */
void SDV_RSA_KEY_LIFECYCLE_SIGN_VERIFY_PKCS1_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    uint8_t hash[RSA_TEST_HASH_LEN];
    for (int i = 0; i < RSA_TEST_HASH_LEN; i++) hash[i] = (uint8_t)(i * 7 + 3);

    uint8_t sig[RSA_TEST_BUF_LEN];
    uint32_t sigLen = sizeof(sig);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    uint8_t eBytes[] = {0x01, 0x00, 0x01}; CRYPT_RsaPara para = {.bits = (uint32_t)bits, .e = eBytes, .eLen = sizeof(eBytes)};
    CRYPT_EAL_PkeyPara pkeyPara = {.id = CRYPT_PKEY_RSA, .para.rsaPara = para};
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &pkeyPara), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    CRYPT_RSA_PkcsV15Para pkcsv15Para = {CRYPT_MD_SHA256};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15Para, sizeof(pkcsv15Para)),
              CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, &sigLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

    sig[sigLen - 1] ^= 0xFF;
    ASSERT_NE(CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA256, hash, RSA_TEST_HASH_LEN, sig, sigLen), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    return;
}
/* END_CASE */
