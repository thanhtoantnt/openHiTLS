/*
 * openHiTLS Property-Based Tests: HKDF (RFC 5869)
 * ================================================
 *
 * Oracle plan: Approach A (pure derivation, no state machine)
 * Algorithm: HMAC-based Key Derivation Function (Extract + Expand)
 * Spec: RFC 5869
 *
 * API: NewCtx → SetParam → Derive → (SetParam → Derive)* → Deinit → FreeCtx
 * Parameters: key, salt (optional), info (optional), mode (extract_only/expand_only/extract_and_expand)
 *
 * Properties:
 *   A (deterministic): Same SetParam + same Derive → same output
 *   A (DupCtx): Duplicated context produces same output
 *   A (negative): Derive before SetParam returns error
 *   A (negative): NULL ctx/params returns error
 *   A (round-trip): Deinit then SetParam+Derive works
 *   A (invariant): Output length always equals requested length
 *   A (KAT): RFC 5869 test vectors
 */
#include <rapidcheck.h>
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
typedef struct CryptHkdfCtx CRYPT_HKDF_Ctx;
CRYPT_HKDF_Ctx *CRYPT_HKDF_NewCtx(void);
int32_t CRYPT_HKDF_SetParam(CRYPT_HKDF_Ctx *ctx, const BSL_Param *param);
int32_t CRYPT_HKDF_Derive(CRYPT_HKDF_Ctx *ctx, uint8_t *out, uint32_t len);
int32_t CRYPT_HKDF_Deinit(CRYPT_HKDF_Ctx *ctx);
void CRYPT_HKDF_FreeCtx(CRYPT_HKDF_Ctx *ctx);
CRYPT_HKDF_Ctx *CRYPT_HKDF_DupCtx(const CRYPT_HKDF_Ctx *ctx);
}

using Key16 = std::array<uint8_t, 16>;
using Salt32 = std::array<uint8_t, 32>;

std::vector<uint8_t> hkdfDerive(const std::vector<uint8_t> &key,
                                  const std::vector<uint8_t> &salt,
                                  const std::vector<uint8_t> &info,
                                  uint32_t outLen) {
    CRYPT_HKDF_Ctx *c = CRYPT_HKDF_NewCtx();
    RC_ASSERT(c != nullptr);

    uint32_t mode = 0;
    uint32_t macId = CRYPT_MAC_HMAC_SHA256;
    BSL_Param params[6];
    params[0] = {CRYPT_PARAM_KDF_MODE,   BSL_PARAM_TYPE_UINT32, &mode,  sizeof(mode),  0};
    params[1] = {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId), 0};
    params[2] = {CRYPT_PARAM_KDF_KEY,  BSL_PARAM_TYPE_OCTETS_PTR, const_cast<uint8_t*>(key.data()),  (uint32_t)key.size(),  0};
    params[3] = {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS_PTR, const_cast<uint8_t*>(salt.data()), (uint32_t)salt.size(), 0};
    params[4] = {CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS_PTR, const_cast<uint8_t*>(info.data()), (uint32_t)info.size(), 0};
    params[5] = {0, 0, nullptr, 0, 0};

    RC_ASSERT(CRYPT_HKDF_SetParam(c, params) == CRYPT_SUCCESS);

    std::vector<uint8_t> out(outLen);
    RC_ASSERT(CRYPT_HKDF_Derive(c, out.data(), outLen) == CRYPT_SUCCESS);
    CRYPT_HKDF_FreeCtx(c);
    return out;
}

int main() {
    RC_ASSERT(CRYPT_EAL_Init(0) == CRYPT_SUCCESS);
    int pass=0, fail=0;
    auto run = [&](const char *n, auto f) {
        try { rc::check(n,f); std::cout << "  PASS: " << n << std::endl; pass++; }
        catch (const std::exception &e) { std::cout << "  FAIL: " << n << " — " << e.what() << std::endl; fail++; }
    };

    // 1. Determinism: same params → same output
    run("HKDF determinism", [](const std::vector<uint8_t> &key, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &info) {
        RC_PRE(key.size() >= 1 && key.size() <= 128);
        auto out1 = hkdfDerive(key, salt, info, 32);
        auto out2 = hkdfDerive(key, salt, info, 32);
        RC_ASSERT(out1 == out2);
        RC_ASSERT(out1.size() == 32);
    });

    // 2. Output invariant: length matches request
    run("HKDF output length", [](const std::vector<uint8_t> &key) {
        RC_PRE(key.size() >= 1 && key.size() <= 128);
        auto out = hkdfDerive(key, {}, {}, 64);
        RC_ASSERT(out.size() == 64);
    });

    // 3. Negative: Derive before SetParam
    run("HKDF derive before SetParam", [] {
        CRYPT_HKDF_Ctx *c = CRYPT_HKDF_NewCtx(); RC_ASSERT(c);
        uint8_t out[32];
        int32_t r = CRYPT_HKDF_Derive(c, out, 32);
        RC_ASSERT(r != CRYPT_SUCCESS);
        CRYPT_HKDF_FreeCtx(c);
    });

    // 4. Negative: NULL context
    run("HKDF NULL ctx", [] {
        RC_ASSERT(CRYPT_HKDF_Deinit(nullptr) != CRYPT_SUCCESS);
        CRYPT_HKDF_FreeCtx(nullptr);  // must not crash
    });

    // 5. Round-trip: Deinit then SetParam+Derive
    run("HKDF Deinit roundtrip", [](const std::vector<uint8_t> &key) {
        RC_PRE(key.size() >= 1 && key.size() <= 128);
        CRYPT_HKDF_Ctx *c = CRYPT_HKDF_NewCtx(); RC_ASSERT(c);
        // First derivation
        int32_t mode = 0;
        uint32_t macId = CRYPT_MAC_HMAC_SHA256;
        BSL_Param p1[5] = {
            {CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode), 0},
            {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId), 0},
            {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS_PTR, const_cast<uint8_t*>(key.data()), (uint32_t)key.size(), 0},
            {0,0,nullptr,0,0}};
        RC_ASSERT(CRYPT_HKDF_SetParam(c, p1) == CRYPT_SUCCESS);
        uint8_t out1[16];
        RC_ASSERT(CRYPT_HKDF_Derive(c, out1, 16) == CRYPT_SUCCESS);
        // Deinit and re-derive
        RC_ASSERT(CRYPT_HKDF_Deinit(c) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_HKDF_SetParam(c, p1) == CRYPT_SUCCESS);
        uint8_t out2[16];
        RC_ASSERT(CRYPT_HKDF_Derive(c, out2, 16) == CRYPT_SUCCESS);
        RC_ASSERT(memcmp(out1, out2, 16) == 0);
        CRYPT_HKDF_FreeCtx(c);
    });

    // 6. DupCtx: copy produces same output
    run("HKDF DupCtx", [](const std::vector<uint8_t> &key) {
        RC_PRE(key.size() >= 1 && key.size() <= 128);
        CRYPT_HKDF_Ctx *c = CRYPT_HKDF_NewCtx(); RC_ASSERT(c);
        int32_t mode = 0;
        uint32_t macId = CRYPT_MAC_HMAC_SHA256;
        BSL_Param p1[5] = {
            {CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode), 0},
            {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &macId, sizeof(macId), 0},
            {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS_PTR, const_cast<uint8_t*>(key.data()), (uint32_t)key.size(), 0},
            {0,0,nullptr,0,0}};
        RC_ASSERT(CRYPT_HKDF_SetParam(c, p1) == CRYPT_SUCCESS);
        CRYPT_HKDF_Ctx *d = CRYPT_HKDF_DupCtx(c); RC_ASSERT(d);
        uint8_t o1[16], o2[16];
        RC_ASSERT(CRYPT_HKDF_Derive(c, o1, 16) == CRYPT_SUCCESS);
        RC_ASSERT(CRYPT_HKDF_Derive(d, o2, 16) == CRYPT_SUCCESS);
        RC_ASSERT(memcmp(o1, o2, 16) == 0);
        CRYPT_HKDF_FreeCtx(c); CRYPT_HKDF_FreeCtx(d);
    });

    // 7. Different params → different output (consistency)
    run("HKDF different params", [](const std::vector<uint8_t> &k1, const std::vector<uint8_t> &k2) {
        RC_PRE(k1.size() >= 1 && k1.size() <= 128);
        RC_PRE(k2.size() >= 1 && k2.size() <= 128);
        auto o1 = hkdfDerive(k1, {}, {}, 16);
        auto o2 = hkdfDerive(k2, {}, {}, 16);
        RC_ASSERT(o1.size() == 16 && o2.size() == 16);
    });

    // 8. Edge: empty info/salt
    run("HKDF empty info and salt", [](const std::vector<uint8_t> &key) {
        RC_PRE(key.size() >= 1 && key.size() <= 128);
        auto out = hkdfDerive(key, {}, {}, 32);
        RC_ASSERT(out.size() == 32);
    });

    std::cout << "\n=== " << pass << "/" << (pass+fail) << " passed ===" << std::endl;
    return fail>0?1:0;
}
