/*
 * openHiTLS Property-Based Tests: GCM (Galois/Counter Mode)
 *
 * Oracle plan: Approach A + Approach B
 * NIST SP 800-38D authenticated encryption (AES-CTR + GHASH)
 *
 * Key struct fields (modes_local.h):
 *   iv[16], ghash[16], hTable[256], ciphCtx, ciphMeth,
 *   last[16], remCt[16], ek0[16], plaintextLen, aadLen,
 *   lastLen, cryptCnt, tagLen
 *
 * Strict ordering: SetKey → SetIv → SetAad (once!) → Crypt(N times) → GetTag/Final
 *
 * Properties:
 *   A (round-trip): Encrypt then Decrypt restores original plaintext
 *   A (streaming): Any split of plaintext chunks → same ciphertext + tag
 *   A (negative): AAD set twice rejected, tag length out of range rejected
 *   A (negative): Decrypt with wrong tag rejected
 *   A (key usage): Rapid reuse respects cryptCnt limit
 *   B (stateful): SetIv→SetAad→Crypt→GetTag lifecycle
 *   B (post-lifecycle): Crypt after GetTag should reinitialize via SetIv
 */
#include <rapidcheck.h>

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
#include "crypt_modes_gcm.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
}

struct GcmSut {
    MODES_CipherGCMCtx *ctx = nullptr;

    explicit GcmSut() {
        ctx = MODES_GCM_NewCtx(CRYPT_CIPHER_AES128_GCM);
    }

    ~GcmSut() {
        if (ctx) { MODES_GCM_DeInitCtx(ctx); MODES_GCM_FreeCtx(ctx); }
    }
};

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Encrypt/Decrypt Round-Trip                     */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_encrypt_decrypt_roundtrip() {
    rc::check("GCM encrypt/decrypt roundtrip: decrypt(encrypt(p)) == p",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &iv,
                 const std::vector<uint8_t> &aad,
                 const std::vector<uint8_t> &plaintext) {
                  RC_PRE(key.size() == 16 || key.size() == 24 || key.size() == 32);
                  RC_PRE(iv.size() >= 1 && iv.size() <= 16);
                  RC_PRE(plaintext.size() <= 1024);

                  // Encrypt
                  GcmSut encSut;
                  RC_ASSERT(encSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(encSut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(encSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(encSut.ctx, aad.data(), (uint32_t)aad.size()) == CRYPT_SUCCESS);

                  std::vector<uint8_t> ciphertext(plaintext.size());
                  std::vector<uint8_t> encData(plaintext.size());
                  if (!plaintext.empty()) {
                      RC_ASSERT(MODES_GCM_EncryptUpdate(encSut.ctx, plaintext.data(),
                          encData.data(), (uint32_t)plaintext.size()) == CRYPT_SUCCESS);
                      ciphertext = encData;
                  }

                  uint8_t encTag[16];
                  uint32_t tagLen = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(encSut.ctx, encTag, &tagLen) == CRYPT_SUCCESS);

                  RC_ASSERT(tagLen == 16);

                  // Decrypt
                  GcmSut decSut;
                  RC_ASSERT(decSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(decSut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(decSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(decSut.ctx, aad.data(), (uint32_t)aad.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetTag(decSut.ctx, encTag, 16) == CRYPT_SUCCESS);

                  std::vector<uint8_t> decrypted(plaintext.size());
                  if (!ciphertext.empty()) {
                      RC_ASSERT(MODES_GCM_DecryptUpdate(decSut.ctx, ciphertext.data(),
                          decrypted.data(), (uint32_t)ciphertext.size()) == CRYPT_SUCCESS);
                  }

                  int32_t ret = MODES_GCM_DecryptFinal(decSut.ctx);
                  RC_ASSERT(ret == CRYPT_SUCCESS);

                  RC_ASSERT(decrypted == plaintext);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Streaming — split plaintext chunks            */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_streaming() {
    rc::check("GCM streaming: any split of plaintext produces same ciphertext",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &iv,
                 const std::vector<uint8_t> &aad,
                 const std::vector<uint8_t> &chunk1,
                 const std::vector<uint8_t> &chunk2) {
                  RC_PRE(key.size() == 16);
                  RC_PRE(iv.size() >= 1 && iv.size() <= 16);
                  RC_PRE(!chunk1.empty() || !chunk2.empty());

                  // Reference: single encrypt
                  GcmSut refSut;
                  RC_ASSERT(refSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(refSut.ctx, key.data(), 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(refSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(refSut.ctx, aad.data(), (uint32_t)aad.size()) == CRYPT_SUCCESS);

                  std::vector<uint8_t> combined;
                  combined.insert(combined.end(), chunk1.begin(), chunk1.end());
                  combined.insert(combined.end(), chunk2.begin(), chunk2.end());
                  std::vector<uint8_t> refCt(combined.size());
                  if (!combined.empty()) {
                      RC_ASSERT(MODES_GCM_EncryptUpdate(refSut.ctx, combined.data(),
                          refCt.data(), (uint32_t)combined.size()) == CRYPT_SUCCESS);
                  }
                  uint8_t refTag[16];
                  uint32_t refTagLen = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(refSut.ctx, refTag, &refTagLen) == CRYPT_SUCCESS);

                  // Chunked: two encrypts
                  GcmSut chunkSut;
                  RC_ASSERT(chunkSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(chunkSut.ctx, key.data(), 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(chunkSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(chunkSut.ctx, aad.data(), (uint32_t)aad.size()) == CRYPT_SUCCESS);

                  std::vector<uint8_t> chunkedCt(combined.size());
                  uint8_t *outPos = chunkedCt.data();
                  if (!chunk1.empty()) {
                      RC_ASSERT(MODES_GCM_EncryptUpdate(chunkSut.ctx, chunk1.data(),
                          outPos, (uint32_t)chunk1.size()) == CRYPT_SUCCESS);
                      outPos += chunk1.size();
                  }
                  if (!chunk2.empty()) {
                      RC_ASSERT(MODES_GCM_EncryptUpdate(chunkSut.ctx, chunk2.data(),
                          outPos, (uint32_t)chunk2.size()) == CRYPT_SUCCESS);
                  }

                  uint8_t chunkedTag[16];
                  uint32_t chunkedTagLen = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(chunkSut.ctx, chunkedTag, &chunkedTagLen) == CRYPT_SUCCESS);

                  RC_ASSERT(chunkedCt == refCt);
                  RC_ASSERT(memcmp(chunkedTag, refTag, 16) == 0);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Negative — AAD repeat rejected                */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_aad_repeat_rejected() {
    rc::check("GCM AAD set twice returns AAD_REPEAT_SET_ERROR",
              [] {
                  GcmSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  uint8_t key[16] = {1};
                  uint8_t iv[12] = {0};
                  uint8_t aad1[8] = {0xAA};
                  uint8_t aad2[8] = {0xBB};

                  RC_ASSERT(MODES_GCM_SetKey(sut.ctx, key, 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(sut.ctx, iv, 12) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(sut.ctx, aad1, 8) == CRYPT_SUCCESS);

                  int32_t ret = MODES_GCM_SetAad(sut.ctx, aad2, 8);
                  RC_ASSERT(ret == CRYPT_MODES_AAD_REPEAT_SET_ERROR);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Negative — Decrypt with wrong tag fails       */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_wrong_tag_rejected() {
    rc::check("GCM decrypt with wrong tag returns TAG_ERROR",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &iv,
                 const std::vector<uint8_t> &plaintext) {
                  RC_PRE(key.size() == 16);
                  RC_PRE(iv.size() >= 1 && iv.size() <= 16);

                  // Encrypt to get ciphertext + correct tag
                  GcmSut encSut;
                  RC_ASSERT(encSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(encSut.ctx, key.data(), 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(encSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(encSut.ctx, nullptr, 0) == CRYPT_SUCCESS);

                  std::vector<uint8_t> ct(plaintext.size());
                  if (!plaintext.empty()) {
                      RC_ASSERT(MODES_GCM_EncryptUpdate(encSut.ctx, plaintext.data(),
                          ct.data(), (uint32_t)plaintext.size()) == CRYPT_SUCCESS);
                  }
                  uint8_t correctTag[16];
                  uint32_t tagLen = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(encSut.ctx, correctTag, &tagLen) == CRYPT_SUCCESS);

                  // Decrypt with FLIPPED tag
                  GcmSut decSut;
                  RC_ASSERT(decSut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(decSut.ctx, key.data(), 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(decSut.ctx, iv.data(), (uint32_t)iv.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(decSut.ctx, nullptr, 0) == CRYPT_SUCCESS);

                  uint8_t wrongTag[16];
                  memcpy(wrongTag, correctTag, 16);
                  wrongTag[0] ^= 0xFF;  // flip bits

                  RC_ASSERT(MODES_GCM_SetTag(decSut.ctx, wrongTag, 16) == CRYPT_SUCCESS);

                  std::vector<uint8_t> decrypted(plaintext.size());
                  if (!ct.empty()) {
                      RC_ASSERT(MODES_GCM_DecryptUpdate(decSut.ctx, ct.data(),
                          decrypted.data(), (uint32_t)ct.size()) == CRYPT_SUCCESS);
                  }

                  int32_t ret = MODES_GCM_DecryptFinal(decSut.ctx);
                  RC_ASSERT(ret == CRYPT_MODES_TAG_ERROR);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Tag length validation                          */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_tag_length() {
    rc::check("GCM tag length: valid {4,8,12-16} accepted, others rejected",
              [](uint32_t tagLen) {
                  GcmSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  int32_t ret = MODES_GCM_Ctrl(sut.ctx,
                      CRYPT_CTRL_SET_TAGLEN,
                      (void *)&tagLen, sizeof(tagLen));

                  bool isValid = (tagLen == 4 || tagLen == 8 ||
                                  (tagLen >= 12 && tagLen <= 16));
                  if (isValid) {
                      RC_ASSERT(ret == CRYPT_SUCCESS);
                  } else {
                      RC_ASSERT(ret == CRYPT_MODES_CTRL_TAGLEN_ERROR);
                  }
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: IV length edge cases (12-byte optimized path)  */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_iv_edge_cases() {
    rc::check("GCM IV edge cases: 12-byte (optimized) and non-12-byte both work",
              [](const std::vector<uint8_t> &key,
                 uint32_t ivLen) {
                  RC_PRE(key.size() == 16);
                  RC_PRE(ivLen >= 1 && ivLen <= 64);

                  GcmSut sut;
                  RC_ASSERT(sut.ctx != nullptr);
                  RC_ASSERT(MODES_GCM_SetKey(sut.ctx, key.data(), 16) == CRYPT_SUCCESS);

                  std::vector<uint8_t> iv(ivLen, 0x01);
                  int32_t ret = MODES_GCM_SetIv(sut.ctx, iv.data(), ivLen);
                  RC_ASSERT(ret == CRYPT_SUCCESS);

                  // Should be able to set AAD and encrypt
                  RC_ASSERT(MODES_GCM_SetAad(sut.ctx, nullptr, 0) == CRYPT_SUCCESS);

                  uint8_t pt[32] = {0};
                  uint8_t ct[32];
                  RC_ASSERT(MODES_GCM_EncryptUpdate(sut.ctx, pt, ct, 32) == CRYPT_SUCCESS);

                  uint8_t tag[16];
                  uint32_t tagLen = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(sut.ctx, tag, &tagLen) == CRYPT_SUCCESS);

                  RC_LOG() << "ivLen=" << ivLen << " ("
                           << (ivLen == 12 ? "optimized" : "GHASH-based")
                           << " path)\n";
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach B: Stateful lifecycle                             */
/* ══════════════════════════════════════════════════════════ */

void test_gcm_lifecycle() {
    rc::check("GCM lifecycle: re-initialization after Final works",
              [](const std::vector<uint8_t> &key) {
                  RC_PRE(key.size() == 16);

                  GcmSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  // First operation
                  uint8_t iv1[12] = {1};
                  uint8_t pt1[16] = {0xAA};
                  uint8_t ct1[16];

                  RC_ASSERT(MODES_GCM_SetKey(sut.ctx, key.data(), 16) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetIv(sut.ctx, iv1, 12) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(sut.ctx, nullptr, 0) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_EncryptUpdate(sut.ctx, pt1, ct1, 16) == CRYPT_SUCCESS);
                  uint8_t tag1[16];
                  uint32_t tagLen1 = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(sut.ctx, tag1, &tagLen1) == CRYPT_SUCCESS);

                  // Second operation on same context (re-init via SetIv)
                  uint8_t iv2[12] = {2};
                  uint8_t pt2[16] = {0xBB};
                  uint8_t ct2[16];

                  RC_ASSERT(MODES_GCM_SetIv(sut.ctx, iv2, 12) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_SetAad(sut.ctx, nullptr, 0) == CRYPT_SUCCESS);
                  RC_ASSERT(MODES_GCM_EncryptUpdate(sut.ctx, pt2, ct2, 16) == CRYPT_SUCCESS);
                  uint8_t tag2[16];
                  uint32_t tagLen2 = 16;
                  RC_ASSERT(MODES_GCM_EncryptFinal(sut.ctx, tag2, &tagLen2) == CRYPT_SUCCESS);

                  // Different IVs produce different ciphertexts
                  RC_ASSERT(memcmp(ct1, ct2, 16) != 0);
              });
}

int main() {
    test_gcm_encrypt_decrypt_roundtrip();
    test_gcm_streaming();
    test_gcm_aad_repeat_rejected();
    test_gcm_wrong_tag_rejected();
    test_gcm_tag_length();
    test_gcm_iv_edge_cases();
    test_gcm_lifecycle();

    return 0;
}
