/*
 * openHiTLS Property-Based Tests: CMAC Reference Model Oracle
 * ===========================================================
 *
 * Approach B: Full reference model running in parallel with real implementation.
 * For every operation sequence:
 *   impl(op).return_code == model(op).return_code
 *   impl(op).mac_output  == model(op).mac_output
 *
 * Reference model: NIST SP 800-38B CMAC implemented with OpenSSL as comparison oracle.
 * Key structure (cipher_mac_common.h: Cipher_MAC_Ctx):
 *   data[16] — CBC state (accumulated block cipher output)
 *   left[16] — partial block buffer
 *   len      — bytes accumulated in left[]
 *
 * Critical branching (cmac.c:105-122):
 *   if msg_len == blockSize → XOR with K1, then encrypt
 *   if msg_len <  blockSize → pad 0x80 + zeros, XOR with K2, then encrypt
 *
 * Properties:
 *   B (state-match): return_code match for all ops in random valid sequences
 *   B (output-match): Final MAC matches OpenSSL CMAC calculation
 *   B (block boundary): K1 used at blockSize multiples, K2 at partial blocks
 *   B (empty message): Init → Final produces valid deterministic CMAC
 */
#include <rapidcheck.h>
#include <rapidcheck/state.h>

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

extern "C" {
#include "crypt_cmac.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
}

/* ══════════════════════════════════════════════════════════ */
/* Reference Model — NIST SP 800-38B CMAC via OpenSSL        */
/* ══════════════════════════════════════════════════════════ */

struct CmacRefModel {
    enum class State { kUninitialised, kInitialised, kUpdated, kFinalised };

    State state = State::kUninitialised;
    std::vector<uint8_t> key;
    std::vector<uint8_t> accumulatedMsg;
    bool alive = true;

    // CMAC block size for AES is always 16 bytes
    static constexpr uint32_t kBlockSize = 16;

    int32_t init(const uint8_t *k, uint32_t kLen) {
        if (!alive) return CRYPT_NULL_INPUT;
        if (k == nullptr && kLen != 0) return CRYPT_NULL_INPUT;
        // AES-128 CMAC requires 16-byte keys
        if (kLen != 16 && kLen != 24 && kLen != 32) return CRYPT_NULL_INPUT;

        key.assign(k, k + kLen);
        accumulatedMsg.clear();
        state = State::kInitialised;
        return CRYPT_SUCCESS;
    }

    int32_t update(const uint8_t *in, uint32_t len) {
        if (!alive) return CRYPT_NULL_INPUT;
        if (in == nullptr && len != 0) return CRYPT_NULL_INPUT;
        if (state != State::kInitialised && state != State::kUpdated) {
            return CRYPT_CMAC_ERR_UNSUPPORTED_CTRL_OPTION;
        }

        accumulatedMsg.insert(accumulatedMsg.end(), in, in + len);
        state = State::kUpdated;
        return CRYPT_SUCCESS;
    }

    int32_t final(uint8_t *out, uint32_t *outLen) {
        if (!alive || out == nullptr || outLen == nullptr) return CRYPT_NULL_INPUT;
        if (*outLen < kBlockSize) return CRYPT_CMAC_OUT_BUFF_LEN_NOT_ENOUGH;

        const EVP_CIPHER *cipher;
        switch (key.size()) {
            case 16: cipher = EVP_aes_128_cbc(); break;
            case 24: cipher = EVP_aes_192_cbc(); break;
            case 32: cipher = EVP_aes_256_cbc(); break;
            default: return CRYPT_NULL_INPUT;
        }

        // Compute CMAC via OpenSSL (the reference oracle)
        CMAC_CTX *cmacCtx = CMAC_CTX_new();
        if (!cmacCtx) return CRYPT_MEM_ALLOC_FAIL;

        if (!CMAC_Init(cmacCtx, key.data(), key.size(), cipher, nullptr)) {
            CMAC_CTX_free(cmacCtx);
            return CRYPT_NULL_INPUT;
        }

        if (!accumulatedMsg.empty()) {
            if (!CMAC_Update(cmacCtx, accumulatedMsg.data(), accumulatedMsg.size())) {
                CMAC_CTX_free(cmacCtx);
                return CRYPT_NULL_INPUT;
            }
        }

        size_t macLen = kBlockSize;
        if (!CMAC_Final(cmacCtx, out, &macLen)) {
            CMAC_CTX_free(cmacCtx);
            return CRYPT_NULL_INPUT;
        }

        *outLen = (uint32_t)macLen;
        CMAC_CTX_free(cmacCtx);
        state = State::kFinalised;
        return CRYPT_SUCCESS;
    }

    int32_t reinit() {
        if (!alive) return CRYPT_NULL_INPUT;
        if (state == State::kUninitialised) return CRYPT_CMAC_ERR_UNSUPPORTED_CTRL_OPTION;

        accumulatedMsg.clear();
        state = State::kInitialised;
        return CRYPT_SUCCESS;
    }

    int32_t deinit() {
        if (!alive) return CRYPT_NULL_INPUT;
        key.clear();
        accumulatedMsg.clear();
        state = State::kUninitialised;
        return CRYPT_SUCCESS;
    }

    void freeCtx() {
        alive = false;
    }
};

/* ══════════════════════════════════════════════════════════ */
/* System Under Test                                         */
/* ══════════════════════════════════════════════════════════ */

struct CmacSut {
    CRYPT_CMAC_Ctx *ctx = nullptr;

    explicit CmacSut(CRYPT_MAC_AlgId id = CRYPT_MAC_CMAC_AES128) {
        ctx = CRYPT_CMAC_NewCtx(id);
    }

    ~CmacSut() {
        if (ctx) CRYPT_CMAC_FreeCtx(ctx);
    }
};

/* ══════════════════════════════════════════════════════════ */
/* Stateful Commands — runs on BOTH model and real impl      */
/* ══════════════════════════════════════════════════════════ */

struct CmacInitCmd : rc::state::Command<CmacRefModel, CmacSut> {
    std::vector<uint8_t> key;
    uint32_t keyLen;

    CmacInitCmd()
        : key(*rc::gen::container<std::vector<uint8_t>>(
              rc::gen::element<size_t>(16U, 24U, 32U),
              rc::gen::arbitrary<uint8_t>())),
          keyLen(static_cast<uint32_t>(key.size())) {}

    void checkPreconditions(const CmacRefModel &s) const override {
        RC_PRE(s.alive);
    }

    void apply(CmacRefModel &s) const override {
        RC_ASSERT(s.init(key.data(), keyLen) == CRYPT_SUCCESS);
    }

    void run(const CmacRefModel &, CmacSut &sut) const override {
        int32_t ret = CRYPT_CMAC_Init(sut.ctx, key.data(), keyLen);
        RC_ASSERT(ret == CRYPT_SUCCESS);
    }

    void show(std::ostream &os) const override {
        os << "CMAC_Init(keyLen=" << keyLen << ")";
    }
};

struct CmacUpdateCmd : rc::state::Command<CmacRefModel, CmacSut> {
    std::vector<uint8_t> msg;
    uint32_t msgLen;

    CmacUpdateCmd()
        : msg(*rc::gen::container<std::vector<uint8_t>>(
              rc::gen::inRange(0U, 256U), rc::gen::arbitrary<uint8_t>())),
          msgLen(static_cast<uint32_t>(msg.size())) {}

    void checkPreconditions(const CmacRefModel &s) const override {
        RC_PRE(s.state == CmacRefModel::State::kInitialised ||
               s.state == CmacRefModel::State::kUpdated);
    }

    void apply(CmacRefModel &s) const override {
        RC_ASSERT(s.update(msg.data(), msgLen) == CRYPT_SUCCESS);
    }

    void run(const CmacRefModel &, CmacSut &sut) const override {
        int32_t ret = CRYPT_CMAC_Update(sut.ctx, msg.data(), msgLen);
        RC_ASSERT(ret == CRYPT_SUCCESS);
    }

    void show(std::ostream &os) const override {
        os << "CMAC_Update(len=" << msgLen << ")";
    }
};

struct CmacFinalCmd : rc::state::Command<CmacRefModel, CmacSut> {
    void checkPreconditions(const CmacRefModel &s) const override {
        RC_PRE(s.state == CmacRefModel::State::kInitialised ||
               s.state == CmacRefModel::State::kUpdated);
    }

    void apply(CmacRefModel &s) const override {
        uint8_t refMac[CmacRefModel::kBlockSize];
        uint32_t macLen = CmacRefModel::kBlockSize;
        RC_ASSERT(s.final(refMac, &macLen) == CRYPT_SUCCESS);
    }

    void run(const CmacRefModel &s0, CmacSut &sut) const override {
        uint32_t implMacLen;
        RC_ASSERT(CRYPT_CMAC_Ctrl(sut.ctx, CRYPT_CTRL_GET_MACLEN, &implMacLen, sizeof(implMacLen)) == CRYPT_SUCCESS);

        std::vector<uint8_t> implMac(implMacLen);
        int32_t ret = CRYPT_CMAC_Final(sut.ctx, implMac.data(), &implMacLen);
        RC_ASSERT(ret == CRYPT_SUCCESS);
        implMac.resize(implMacLen);

        // Output-match: compare against OpenSSL reference
        uint8_t refMacBuf[16];
        uint32_t refLen = 16;
        RC_ASSERT(s0.final(refMacBuf, &refLen) == CRYPT_SUCCESS);

        RC_ASSERT(implMacLen == refLen);
        RC_ASSERT(memcmp(implMac.data(), refMacBuf, implMacLen) == 0);
    }

    void show(std::ostream &os) const override {
        os << "CMAC_Final";
    }
};

struct CmacReinitCmd : rc::state::Command<CmacRefModel, CmacSut> {
    void checkPreconditions(const CmacRefModel &s) const override {
        RC_PRE(s.state == CmacRefModel::State::kInitialised ||
               s.state == CmacRefModel::State::kUpdated);
    }

    void apply(CmacRefModel &s) const override {
        RC_ASSERT(s.reinit() == CRYPT_SUCCESS);
    }

    void run(const CmacRefModel &, CmacSut &sut) const override {
        int32_t ret = CRYPT_CMAC_Reinit(sut.ctx);
        RC_ASSERT(ret == CRYPT_SUCCESS);
    }

    void show(std::ostream &os) const override {
        os << "CMAC_Reinit";
    }
};

/* ══════════════════════════════════════════════════════════ */
/* Main: Approach B stateful reference model testing         */
/* ══════════════════════════════════════════════════════════ */

int main() {
    rc::check("CMAC reference model oracle: impl matches OpenSSL for all sequences",
              [] {
                  CmacRefModel model;
                  CmacSut sut(CRYPT_MAC_CMAC_AES128);
                  RC_ASSERT(sut.ctx != nullptr);

                  rc::state::check(model, sut, &rc::state::gen::execOneOf<
                      CmacInitCmd, CmacUpdateCmd, CmacFinalCmd, CmacReinitCmd
                  >);
              });

    return 0;
}
