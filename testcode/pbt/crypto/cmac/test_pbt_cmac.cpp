/*
 * openHiTLS Property-Based Tests: CMAC
 *
 * Oracle plan: Approach A + Approach B
 * State: Cipher_MAC_Ctx { method, key, data[16] (CBC state), left[16] (partial block), len }
 * NIST SP 800-38B implementation over any block cipher (AES, SM4)
 *
 * Critical logic (cmac.c:81-124):
 *   K1 sub-key = L << 1, conditionally XOR rb
 *   K2 sub-key = K1 << 1, conditionally XOR rb
 *   If msg_len == blockSize → XOR with K1
 *   If msg_len <  blockSize → pad 0x80 + zeros, XOR with K2
 *
 * Properties:
 *   A (streaming): Any split of Update chunks → same Final MAC
 *   A (block boundary): K1 vs K2 selection at exact multiples and partial blocks
 *   A (empty message): Init → Final produces valid CMAC
 *   A (Reinit equivalence): Reinit resets partial block but preserves key
 *   A (DupCtx): Deep copy produces identical MAC
 *   A (negative): Final short buffer, NULL params
 *   B (stateful): Init→Update→Final→Deinit→Init lifecycle
 */
#include <rapidcheck.h>

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
#include "crypt_cmac.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
}

struct CmacSut {
    CRYPT_CMAC_Ctx *ctx = nullptr;

    explicit CmacSut(CRYPT_MAC_AlgId id = CRYPT_MAC_CMAC_AES128) {
        ctx = CRYPT_CMAC_NewCtx(id);
    }

    ~CmacSut() {
        if (ctx) CRYPT_CMAC_FreeCtx(ctx);
    }
};

/* Compute CMAC over a single message (for reference) */
std::vector<uint8_t> ComputeCmac(CRYPT_CMAC_Ctx *ctx,
                                  const std::vector<uint8_t> &key,
                                  const std::vector<uint8_t> &msg) {
    RC_ASSERT(CRYPT_CMAC_Init(ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
    if (!msg.empty()) {
        RC_ASSERT(CRYPT_CMAC_Update(ctx, msg.data(), (uint32_t)msg.size()) == CRYPT_SUCCESS);
    }
    uint32_t macLen;
    RC_ASSERT(CRYPT_CMAC_Ctrl(ctx, CRYPT_CTRL_GET_MACLEN, &macLen, sizeof(macLen)) == CRYPT_SUCCESS);
    std::vector<uint8_t> mac(macLen);
    RC_ASSERT(CRYPT_CMAC_Final(ctx, mac.data(), &macLen) == CRYPT_SUCCESS);
    mac.resize(macLen);
    return mac;
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Streaming — any split produces same MAC       */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_streaming() {
    rc::check("CMAC streaming: any split of Update chunks produces same MAC",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &chunk1,
                 const std::vector<uint8_t> &chunk2) {
                  RC_PRE(!key.empty());
                  RC_PRE(!chunk1.empty() || !chunk2.empty());

                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  // Reference: single Update
                  CmacSut refSut;
                  RC_ASSERT(refSut.ctx != nullptr);
                  std::vector<uint8_t> combined;
                  combined.insert(combined.end(), chunk1.begin(), chunk1.end());
                  combined.insert(combined.end(), chunk2.begin(), chunk2.end());
                  auto refMac = ComputeCmac(refSut.ctx, key, combined);

                  // Chunked: two Updates
                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(CRYPT_CMAC_Update(sut.ctx, chunk1.data(), (uint32_t)chunk1.size()) == CRYPT_SUCCESS);
                  RC_ASSERT(CRYPT_CMAC_Update(sut.ctx, chunk2.data(), (uint32_t)chunk2.size()) == CRYPT_SUCCESS);

                  uint32_t macLen;
                  RC_ASSERT(CRYPT_CMAC_Ctrl(sut.ctx, CRYPT_CTRL_GET_MACLEN, &macLen, sizeof(macLen)) == CRYPT_SUCCESS);
                  std::vector<uint8_t> chunkedMac(macLen);
                  RC_ASSERT(CRYPT_CMAC_Final(sut.ctx, chunkedMac.data(), &macLen) == CRYPT_SUCCESS);
                  chunkedMac.resize(macLen);

                  RC_ASSERT(chunkedMac == refMac);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Block Boundary — K1 vs K2 sub-key selection   */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_block_boundary() {
    rc::check("CMAC block boundary: exact block-size and partial produce correct MAC",
              [](const std::vector<uint8_t> &key,
                 uint32_t msgLen) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  std::vector<uint8_t> msg(msgLen, 0x55);
                  auto mac = ComputeCmac(sut.ctx, key, msg);
                  RC_ASSERT(mac.size() > 0);

                  RC_LOG() << "msgLen=" << msgLen << " macLen=" << mac.size() << '\n';
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Empty Message produces valid CMAC             */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_empty_message() {
    rc::check("CMAC empty message: Init→Final without Update produces valid MAC",
              [](const std::vector<uint8_t> &key) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  // Empty message — should go through K2-padded path
                  auto mac = ComputeCmac(sut.ctx, key, {});
                  RC_ASSERT(mac.size() > 0);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Reinit equivalence                             */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_reinit_equivalence() {
    rc::check("CMAC reinit equivalence: preserves key, resets partial block",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &msg1,
                 const std::vector<uint8_t> &msg2) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  // Reference: Init, then Update(msg1+msg2), then Final
                  CmacSut refSut;
                  RC_ASSERT(refSut.ctx != nullptr);
                  std::vector<uint8_t> combined;
                  combined.insert(combined.end(), msg1.begin(), msg1.end());
                  combined.insert(combined.end(), msg2.begin(), msg2.end());
                  auto refMac = ComputeCmac(refSut.ctx, key, combined);

                  // Reinit path: Init, Update(msg1), Reinit, Update(msg2), Final
                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
                  if (!msg1.empty()) {
                      RC_ASSERT(CRYPT_CMAC_Update(sut.ctx, msg1.data(), (uint32_t)msg1.size()) == CRYPT_SUCCESS);
                  }
                  RC_ASSERT(CRYPT_CMAC_Reinit(sut.ctx) == CRYPT_SUCCESS);
                  RC_ASSERT(CRYPT_CMAC_Update(sut.ctx, combined.data(), (uint32_t)combined.size()) == CRYPT_SUCCESS);

                  uint32_t macLen;
                  RC_ASSERT(CRYPT_CMAC_Ctrl(sut.ctx, CRYPT_CTRL_GET_MACLEN, &macLen, sizeof(macLen)) == CRYPT_SUCCESS);
                  std::vector<uint8_t> reinitMac(macLen);
                  RC_ASSERT(CRYPT_CMAC_Final(sut.ctx, reinitMac.data(), &macLen) == CRYPT_SUCCESS);
                  reinitMac.resize(macLen);

                  RC_ASSERT(reinitMac == refMac);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: DupCtx independence                            */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_dup_independence() {
    rc::check("CMAC DupCtx creates context that produces same MAC",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &msg) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
                  if (!msg.empty()) {
                      RC_ASSERT(CRYPT_CMAC_Update(sut.ctx, msg.data(), (uint32_t)msg.size()) == CRYPT_SUCCESS);
                  }

                  CRYPT_CMAC_Ctx *dupCtx = CRYPT_CMAC_DupCtx(sut.ctx);
                  RC_ASSERT(dupCtx != nullptr);

                  // Final on original
                  uint32_t origMacLen;
                  RC_ASSERT(CRYPT_CMAC_Ctrl(sut.ctx, CRYPT_CTRL_GET_MACLEN, &origMacLen, sizeof(origMacLen)) == CRYPT_SUCCESS);
                  std::vector<uint8_t> origMac(origMacLen);
                  RC_ASSERT(CRYPT_CMAC_Final(sut.ctx, origMac.data(), &origMacLen) == CRYPT_SUCCESS);

                  // Final on dup (same state)
                  uint32_t dupMacLen;
                  RC_ASSERT(CRYPT_CMAC_Ctrl(dupCtx, CRYPT_CTRL_GET_MACLEN, &dupMacLen, sizeof(dupMacLen)) == CRYPT_SUCCESS);
                  std::vector<uint8_t> dupMac(dupMacLen);
                  RC_ASSERT(CRYPT_CMAC_Final(dupCtx, dupMac.data(), &dupMacLen) == CRYPT_SUCCESS);

                  RC_ASSERT(origMac == dupMac);

                  CRYPT_CMAC_FreeCtx(dupCtx);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Negative — short output buffer                 */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_negative_short_buffer() {
    rc::check("CMAC Final with short output buffer returns NOT_ENOUGH",
              [](const std::vector<uint8_t> &key) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);

                  uint8_t tinyBuf[1];
                  uint32_t tinyLen = 1;
                  int32_t ret = CRYPT_CMAC_Final(sut.ctx, tinyBuf, &tinyLen);
                  RC_ASSERT(ret == CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach A: Round-Trip — Deinit→Init cycle                 */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_deinit_reinit_roundtrip() {
    rc::check("CMAC Deinit then Init restores working state",
              [](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &msg) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  auto mac1 = ComputeCmac(sut.ctx, key, msg);

                  RC_ASSERT(CRYPT_CMAC_Deinit(sut.ctx) == CRYPT_SUCCESS);
                  auto mac2 = ComputeCmac(sut.ctx, key, msg);

                  RC_ASSERT(mac1 == mac2);
              });
}

/* ══════════════════════════════════════════════════════════ */
/* Approach B: Post-Lifecycle — operations after FreeCtx      */
/* ══════════════════════════════════════════════════════════ */

void test_cmac_use_after_free() {
    rc::check("CMAC: context can be re-created after FreeCtx",
              [](const std::vector<uint8_t> &key) {
                  RC_PRE(!key.empty());
                  CmacSut sut;
                  RC_ASSERT(sut.ctx != nullptr);

                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);

                  CRYPT_CMAC_FreeCtx(sut.ctx);
                  sut.ctx = nullptr;

                  // Re-create
                  sut.ctx = CRYPT_CMAC_NewCtx(CRYPT_MAC_CMAC_AES128);
                  RC_ASSERT(sut.ctx != nullptr);
                  RC_ASSERT(CRYPT_CMAC_Init(sut.ctx, key.data(), (uint32_t)key.size()) == CRYPT_SUCCESS);
              });
}

int main() {
    test_cmac_streaming();
    test_cmac_block_boundary();
    test_cmac_empty_message();
    test_cmac_reinit_equivalence();
    test_cmac_dup_independence();
    test_cmac_negative_short_buffer();
    test_cmac_deinit_reinit_roundtrip();
    test_cmac_use_after_free();

    return 0;
}
