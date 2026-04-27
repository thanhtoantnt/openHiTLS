/*
 * CONFIRMED BUG: SipHash Reinit Produces Wrong MAC
 * =================================================
 *
 * Reproduction: standalone C test — no rapidcheck, no PBT framework.
 * Compile and link against openHiTLS:
 *
 *   clang -I ../../include -I ../../include/crypto -I ../../include/bsl \
 *     -I ../../config/macro_config \
 *     test_bug_reinit_repro.c ../../build/libhitls_crypto.a ../../build/libhitls_bsl.a \
 *     -o test_bug_reinit_repro
 *
 * Run:
 *   ./test_bug_reinit_repro
 *
 * Expected: Direct and Reinit paths produce identical MAC.
 * Actual:   Direct and Reinit paths produce DIFFERENT MACs (BUG).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"

#define SIPHASH_KEY_SIZE  16
#define SIPHASH_OUTPUT_SIZE 8

typedef struct EAL_MacCtx CRYPT_EAL_MacCtx;

extern CRYPT_EAL_MacCtx *CRYPT_EAL_MacNewCtx(CRYPT_MAC_AlgId id);
extern int32_t CRYPT_EAL_MacInit(CRYPT_EAL_MacCtx *ctx, const uint8_t *key, uint32_t len);
extern int32_t CRYPT_EAL_MacUpdate(CRYPT_EAL_MacCtx *ctx, const uint8_t *in, uint32_t len);
extern int32_t CRYPT_EAL_MacFinal(CRYPT_EAL_MacCtx *ctx, uint8_t *out, uint32_t *len);
extern int32_t CRYPT_EAL_MacReinit(CRYPT_EAL_MacCtx *ctx);
extern void CRYPT_EAL_MacFreeCtx(CRYPT_EAL_MacCtx *ctx);

static const uint8_t testKey[SIPHASH_KEY_SIZE] = {0};
static const uint8_t testMsg[2] = {0, 0};

void print_mac(const char *label, const uint8_t *mac, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", mac[len - 1 - i]);
    printf("\n");
}

int main(void) {
    printf("=== SipHash Reinit Bug Reproduction ===\n\n");

    // Initialize library
    int32_t ret = CRYPT_EAL_Init(0);
    if (ret != CRYPT_SUCCESS) { printf("EAL_Init failed: %d\n", ret); return 1; }

    // ── Direct Path: Init → Update → Final ──────────────────
    CRYPT_EAL_MacCtx *ctx1 = CRYPT_EAL_MacNewCtx(CRYPT_MAC_SIPHASH64);
    if (!ctx1) { printf("NewCtx failed\n"); return 1; }

    ret = CRYPT_EAL_MacInit(ctx1, testKey, SIPHASH_KEY_SIZE);
    if (ret != CRYPT_SUCCESS) { printf("Init failed: %d\n", ret); return 1; }

    ret = CRYPT_EAL_MacUpdate(ctx1, testMsg, sizeof(testMsg));
    if (ret != CRYPT_SUCCESS) { printf("Update failed: %d\n", ret); return 1; }

    uint8_t directMac[SIPHASH_OUTPUT_SIZE];
    uint32_t macLen = SIPHASH_OUTPUT_SIZE;
    ret = CRYPT_EAL_MacFinal(ctx1, directMac, &macLen);
    if (ret != CRYPT_SUCCESS) { printf("Final failed: %d\n", ret); return 1; }

    print_mac("DIRECT path MAC  ", directMac, macLen);
    CRYPT_EAL_MacFreeCtx(ctx1);

    // ── Reinit Path: Init → Update1 → Reinit → Update2 → Final
    CRYPT_EAL_MacCtx *ctx2 = CRYPT_EAL_MacNewCtx(CRYPT_MAC_SIPHASH64);
    if (!ctx2) { printf("NewCtx failed\n"); return 1; }

    ret = CRYPT_EAL_MacInit(ctx2, testKey, SIPHASH_KEY_SIZE);
    if (ret != CRYPT_SUCCESS) { printf("Init failed: %d\n", ret); return 1; }

    // Update with first byte only, then Reinit, then Update with both bytes
    ret = CRYPT_EAL_MacUpdate(ctx2, testMsg, 1);
    if (ret != CRYPT_SUCCESS) { printf("Update1 failed: %d\n", ret); return 1; }

    ret = CRYPT_EAL_MacReinit(ctx2);
    if (ret != CRYPT_SUCCESS) { printf("Reinit failed: %d\n", ret); return 1; }

    ret = CRYPT_EAL_MacUpdate(ctx2, testMsg, sizeof(testMsg));
    if (ret != CRYPT_SUCCESS) { printf("Update2 failed: %d\n", ret); return 1; }

    uint8_t reinitMac[SIPHASH_OUTPUT_SIZE];
    uint32_t macLen2 = SIPHASH_OUTPUT_SIZE;
    ret = CRYPT_EAL_MacFinal(ctx2, reinitMac, &macLen2);
    if (ret != CRYPT_SUCCESS) { printf("Final failed: %d\n", ret); return 1; }

    print_mac("REINIT path MAC ", reinitMac, macLen2);
    CRYPT_EAL_MacFreeCtx(ctx2);

    // ── Verify ──────────────────────────────────────────────
    printf("\n");
    if (memcmp(directMac, reinitMac, SIPHASH_OUTPUT_SIZE) == 0) {
        printf("✓ PASS: Direct and Reinit MACs match\n");
        return 0;
    } else {
        printf("✗ BUG CONFIRMED: Direct and Reinit MACs DIFFER\n\n");
        print_mac("  Direct ", directMac, SIPHASH_OUTPUT_SIZE);
        print_mac("  Reinit ", reinitMac, SIPHASH_OUTPUT_SIZE);

        printf("\n  Root cause: CRYPT_SIPHASH_Reinit() zeroes state registers\n");
        printf("  instead of re-deriving them from the original key.\n");
        printf("  The key is not stored in struct SIPHASH_Ctx.\n\n");
        printf("  Affected file: crypto/siphash/src/siphash.c:295-309\n");
        printf("  Fix: store key in struct SIPHASH_Ctx and re-derive\n");
        printf("       state0-state3 from key in CRYPT_SIPHASH_Reinit().\n");
        return 1;
    }
}
