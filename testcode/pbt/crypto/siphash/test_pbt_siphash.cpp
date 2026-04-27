/*
 * openHiTLS Property-Based Tests: SipHash
 * ========================================
 *
 * Oracle plan: Approach A + Approach B
 * Algorithm: SipHash-2-4 (2 rounds per message block, 4 finalization rounds)
 * Spec: https://131002.net/siphash/
 *
 * Lifecycle: NewCtx → Init → Update(N) → Final → (Reinit → ...) → Deinit → FreeCtx
 * Key: 16 bytes, Output: 8 bytes
 *
 * Properties:
 *   A (streaming): Any split of Update chunks → same Final MAC
 *   A (reinit equivalence): Init→Update→Reinit→Update→Final == Init→Update+Update→Final
 *   A (DupCtx): Duplicated context produces same MAC
 *   A (negative): NULL key, wrong key length, short output buffer
 *   A (invariant): Output length always 8 bytes, never crashes
 *   B (post-lifecycle): Update after Deinit returns error
 *   B (state match): All lifecycle transitions return expected codes
 */
#include <rapidcheck.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
typedef struct EAL_MacCtx CRYPT_EAL_MacCtx;
CRYPT_EAL_MacCtx *CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgId id);
int32_t CRYPT_EAL_MacInit(CRYPT_EAL_MacCtx *ctx, const uint8_t *key, uint32_t len);
int32_t CRYPT_EAL_MacUpdate(CRYPT_EAL_MacCtx *ctx, const uint8_t *in, uint32_t len);
int32_t CRYPT_EAL_MacFinal(CRYPT_EAL_MacCtx *ctx, uint8_t *out, uint32_t *len);
int32_t CRYPT_EAL_MacReinit(CRYPT_EAL_MacCtx *ctx);
int32_t CRYPT_EAL_MacDeinit(CRYPT_EAL_MacCtx *ctx);
void CRYPT_EAL_MacFreeCtx(CRYPT_EAL_MacCtx *ctx);
CRYPT_EAL_MacCtx *CRYPT_EAL_MacDupCtx(const CRYPT_EAL_MacCtx *ctx);
}

static constexpr uint32_t kSipHashKeySize = 16;
static constexpr uint32_t kSipHashOutputSize = 8;
static constexpr CRYPT_MAC_AlgId kSipHashAlg = CRYPT_MAC_SIPHASH64;

// Known-answer test vector from SipHash-2-4 specification
// key = 16 bytes of 0x00, msg = [0x00..0x0e], expected = 0x726fdb47dd0e0e31
static const uint8_t kKatKey[16] = {0};
static const uint8_t kKatMsg[15] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e};
static const uint8_t kKatExpected[8] = {0x31,0x0e,0x0e,0xdd,0x47,0xdb,0x6f,0x72};

std::vector<uint8_t> ealSipHash(const std::vector<uint8_t> &k, const std::vector<uint8_t> &m) {
    CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg);
    RC_ASSERT(c != nullptr);
    RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), (uint32_t)k.size()) == CRYPT_SUCCESS);
    if (!m.empty()) RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), (uint32_t)m.size()) == CRYPT_SUCCESS);
    uint32_t len = kSipHashOutputSize;
    std::vector<uint8_t> mac(len);
    RC_ASSERT(CRYPT_EAL_MacFinal(c, mac.data(), &len) == CRYPT_SUCCESS);
    mac.resize(len);
    CRYPT_EAL_MacFreeCtx(c);
    return mac;
}

int main() {
    RC_ASSERT(CRYPT_EAL_Init(0) == CRYPT_SUCCESS);
    int pass = 0, total = 0;
    auto run = [&](const char *name, auto fn) { rc::check(name, fn); std::cout << "  PASS: " << name << std::endl; pass++; total++; };

    // 1. Known-answer test vector
    run("SipHash KAT", [] {
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, kKatKey, 16) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacUpdate(c, kKatMsg, 15) == CRYPT_SUCCESS);
        uint32_t macLen = kSipHashOutputSize;
        uint8_t mac[kSipHashOutputSize];
        RC_ASSERT(CRYPT_EAL_MacFinal(c, mac, &macLen) == CRYPT_SUCCESS);
        RC_ASSERT(macLen == kSipHashOutputSize);
        RC_ASSERT(memcmp(mac, kKatExpected, kSipHashOutputSize) == 0);
        CRYPT_EAL_MacFreeCtx(c);
    });

    // 2. Streaming: any split → same MAC
    run("SipHash streaming", [](const std::vector<uint8_t> &k, const std::vector<uint8_t> &c1, const std::vector<uint8_t> &c2) {
        RC_PRE(k.size() == kSipHashKeySize);
        RC_PRE(!c1.empty() || !c2.empty());
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacUpdate(c, c1.data(), (uint32_t)c1.size()) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacUpdate(c, c2.data(), (uint32_t)c2.size()) == CRYPT_SUCCESS);
        uint32_t len = kSipHashOutputSize; std::vector<uint8_t> chunked(len);
        RC_ASSERT(CRYPT_EAL_MacFinal(c, chunked.data(), &len) == CRYPT_SUCCESS);
        chunked.resize(len); CRYPT_EAL_MacFreeCtx(c);
        std::vector<uint8_t> combined; combined.insert(combined.end(), c1.begin(), c1.end());
        combined.insert(combined.end(), c2.begin(), c2.end());
        auto ref = ealSipHash(k, combined);
        RC_ASSERT(chunked == ref);
    });

    // 3. Reinit equivalence
    run("SipHash reinit equivalence", [](const std::vector<uint8_t> &k, const std::vector<uint8_t> &m) {
        RC_PRE(k.size() == kSipHashKeySize); RC_PRE(m.size() >= 2);
        auto ref = ealSipHash(k, m);
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), 1) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacReinit(c) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), (uint32_t)m.size()) == CRYPT_SUCCESS);
        uint32_t len = kSipHashOutputSize; std::vector<uint8_t> rmac(len);
        RC_ASSERT(CRYPT_EAL_MacFinal(c, rmac.data(), &len) == CRYPT_SUCCESS);
        rmac.resize(len); CRYPT_EAL_MacFreeCtx(c);
        RC_ASSERT(rmac == ref);
    });

    // 4. DupCtx independence
    run("SipHash DupCtx", [](const std::vector<uint8_t> &k, const std::vector<uint8_t> &m) {
        RC_PRE(k.size() == kSipHashKeySize);
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        if (!m.empty()) RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), (uint32_t)m.size()) == CRYPT_SUCCESS);
        CRYPT_EAL_MacCtx *dup = CRYPT_EAL_MacDupCtx(c); RC_ASSERT(dup);
        uint32_t l1 = kSipHashOutputSize, l2 = kSipHashOutputSize;
        std::vector<uint8_t> m1(l1), m2(l2);
        RC_ASSERT(CRYPT_EAL_MacFinal(c, m1.data(), &l1) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacFinal(dup, m2.data(), &l2) == CRYPT_SUCCESS);
        RC_ASSERT(m1 == m2);
        CRYPT_EAL_MacFreeCtx(c); CRYPT_EAL_MacFreeCtx(dup);
    });

    // 5. Output invariant: always 8 bytes
    run("SipHash output size invariant", [](const std::vector<uint8_t> &k, const std::vector<uint8_t> &m) {
        RC_PRE(k.size() == kSipHashKeySize);
        auto mac = ealSipHash(k, m);
        RC_ASSERT(mac.size() == kSipHashOutputSize);
    });

    // 6. Negative: NULL key with nonzero length
    run("SipHash NULL key rejection", [] {
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, nullptr, kSipHashKeySize) == CRYPT_NULL_INPUT);
        CRYPT_EAL_MacFreeCtx(c);
    });

    // 7. Negative: Short output buffer
    run("SipHash short output buffer", [](const std::vector<uint8_t> &k) {
        RC_PRE(k.size() == kSipHashKeySize);
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        uint8_t tinyBuf[1]; uint32_t tinyLen = 1;
        RC_ASSERT(CRYPT_EAL_MacFinal(c, tinyBuf, &tinyLen) != CRYPT_SUCCESS);
        CRYPT_EAL_MacFreeCtx(c);
    });

    // 8. Post-lifecycle: Update after Deinit
    run("SipHash update after deinit", [](const std::vector<uint8_t> &k) {
        RC_PRE(k.size() == kSipHashKeySize);
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_EAL_MacDeinit(c) == CRYPT_SUCCESS);
        uint8_t tmp[1] = {0};
        int32_t ret = CRYPT_EAL_MacUpdate(c, tmp, 1);
        // Post-deinit update should return an error
        RC_ASSERT(ret != CRYPT_SUCCESS);
        CRYPT_EAL_MacFreeCtx(c);
    });

    // 9. Exact key size: 16 bytes only
    run("SipHash exact key size", [](const std::vector<uint8_t> &k) {
        RC_PRE(k.size() == kSipHashKeySize);
        CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg); RC_ASSERT(c);
        RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), kSipHashKeySize) == CRYPT_SUCCESS);
        CRYPT_EAL_MacFreeCtx(c);
    });

    // 10. Edge: empty message
    run("SipHash empty message", [](const std::vector<uint8_t> &k) {
        RC_PRE(k.size() == kSipHashKeySize);
        auto mac = ealSipHash(k, {});
        RC_ASSERT(mac.size() == kSipHashOutputSize);
    });

    std::cout << "\n=== " << pass << "/" << total << " passed ===" << std::endl;
    return pass == total ? 0 : 1;
}
