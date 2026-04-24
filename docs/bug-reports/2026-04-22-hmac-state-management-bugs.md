# Bug Report: openHiTLS HMAC Internal API — Two State Management Defects

**Date:** 2026-04-22
**Component:** `crypto/hmac/src/hmac.c`
**Discovered via:** Property-based testing with reference model automaton
**Severity:** High (BUG-HMAC-1), Medium (BUG-HMAC-2)

---

## Summary

Property-based testing of the internal HMAC API (`CRYPT_HMAC_*`) revealed two
state-management bugs, both rooted in `CRYPT_HMAC_Deinit` not nulling its
sub-context pointers after clearing them.

| ID | Symptom | Severity |
|----|---------|----------|
| BUG-HMAC-1 | Any operation (`Update`, `Reinit`, `Final`) succeeds silently after `Deinit` — producing wrong output | High |
| BUG-HMAC-2 | `Reinit` succeeds from INIT state (before any `Update`) — violates state machine contract | Medium |

Confirmed by running `test_suite_sdv_hmac_internal`:
```
Run 46 testcases, passed: 37, skipped: 0, failed: 9
```

---

## BUG-HMAC-1: Operations Succeed After Deinit — Silent Wrong Output

### Description

`CRYPT_HMAC_Deinit` calls the internal `deinit` method on each of the three sub-contexts
(`mdCtx`, `iCtx`, `oCtx`), clearing their internal hash state, but **does not null those
pointers** afterwards. Method function pointers (`method.update`, `method.copyCtx`, etc.)
are also left intact.

As a result, every subsequent operation passes its NULL guard and runs on cleared state:

```c
// crypto/hmac/src/hmac.c:236 — the bug
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);  // clears state, but...
    (void)ctx->method.deinit(ctx->iCtx);   // ...does NOT null any pointer
    (void)ctx->method.deinit(ctx->oCtx);
    return CRYPT_SUCCESS;
}
```

Because `ctx->mdCtx != NULL` and `ctx->method.update != NULL` after deinit, `CRYPT_HMAC_Update`
passes its guard and calls `method.update` on the cleared context. Likewise, `CRYPT_HMAC_Reinit`
passes its guard (`copyCtx != NULL`) and copies the zeroed `iCtx` into the zeroed `mdCtx`.
A subsequent `CRYPT_HMAC_Final` then succeeds and emits output bytes — but those bytes
are derived from cleared state and are **cryptographically incorrect**.

### Impact

Any caller that invokes `Update`, `Reinit`, or `Final` after `Deinit` (without calling
`Init` again) receives:
- No error signal — return code is `CRYPT_SUCCESS`
- Silently wrong MAC output

This is a correctness and security issue: MAC verification using the wrong output would
accept values it should reject.

### Reproducers

**Case A — Update after Deinit:**
```
SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001 CRYPT_MAC_HMAC_SHA256
```
```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out, &outLen);
CRYPT_HMAC_Deinit(mac);

int32_t ret = CRYPT_HMAC_Update(mac, msg, 64);
ASSERT_NE(ret, CRYPT_SUCCESS);  // FAILS: ret == CRYPT_SUCCESS (0)
```

**Case B — Reinit+Final after Deinit produces wrong output:**
```
SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001 CRYPT_MAC_HMAC_SHA256
```
```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out1, &outLen1);
CRYPT_HMAC_Deinit(mac);

int32_t reinitRet = CRYPT_HMAC_Reinit(mac);         // succeeds — should fail
CRYPT_HMAC_Update(mac, msg, 64);                     // succeeds — on cleared state
int32_t finalRet = CRYPT_HMAC_Final(mac, out2, &outLen2);
ASSERT_NE(finalRet, CRYPT_SUCCESS);  // FAILS: finalRet == CRYPT_SUCCESS (0)
// out2 is wrong output
```

### Run to Reproduce

```bash
cd testcode/script
bash build_sdv.sh run-tests=test_suite_sdv_hmac_internal
bash execute_sdv.sh test_suite_sdv_hmac_internal
# Failing: DEINIT_THEN_UPDATE_TC001, DEINIT_THEN_REINIT_TC001 (3 variants each)
```

### Fix

Null the three sub-context pointers inside `CRYPT_HMAC_Deinit` after clearing them.
This causes all subsequent operation guards to fail correctly:

```c
// crypto/hmac/src/hmac.c — proposed fix
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);
    ctx->mdCtx = NULL;                     // ← ADD
    (void)ctx->method.deinit(ctx->iCtx);
    ctx->iCtx = NULL;                      // ← ADD
    (void)ctx->method.deinit(ctx->oCtx);
    ctx->oCtx = NULL;                      // ← ADD
    return CRYPT_SUCCESS;
}
```

With `mdCtx == NULL`, downstream guards in `Update`, `Reinit`, and `Final` catch the
invalid state and return an error. No changes to those functions are required.

---

## BUG-HMAC-2: Reinit Succeeds from INIT State (Before Any Update)

### Description

`CRYPT_HMAC_Reinit` is intended to reset the running hash back to the post-`Init`
baseline, allowing the same key to be reused for a new message without calling `Init`
again. It should only be callable from UPDATE or FINAL state — after at least one
`Update` or one `Final` has been called.

However, it succeeds when called immediately after `Init`, before any `Update`:

```c
// crypto/hmac/src/hmac.c:226 — the bug
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL) {  // only checks pointers
        ...
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    return CRYPT_SUCCESS;  // always succeeds once Init has run
}
```

The internal `CRYPT_HMAC_Ctx` struct has no state field. `Reinit` only checks that
`copyCtx` is non-NULL, which is true as soon as `Init` has run, so it succeeds from
any post-`Init` state including INIT.

The reference model defines:
```
Reinit is valid from:   UPDATE, FINAL
Reinit is invalid from: NEW, INIT, DEINIT
```

### Impact

Lower severity than BUG-HMAC-1. The output is still correct (calling Reinit from INIT
is a no-op — `iCtx` and `mdCtx` already hold the same state). However, it violates the
state machine contract and prevents callers from detecting incorrect usage.

### Reproducer

```
SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001 CRYPT_MAC_HMAC_SHA256
```
```c
CRYPT_HMAC_Init(mac, key, 32);        // state: INIT
int32_t ret = CRYPT_HMAC_Reinit(mac); // reference model: should return ERR_STATE
ASSERT_NE(ret, CRYPT_SUCCESS);        // FAILS: ret == CRYPT_SUCCESS (0)
```

### Run to Reproduce

```bash
cd testcode/script
bash build_sdv.sh run-tests=test_suite_sdv_hmac_internal
bash execute_sdv.sh test_suite_sdv_hmac_internal
# Failing: REINIT_FROM_INIT_TC001 (3 variants)
```

### Fix

Add a `hasData` flag to `CRYPT_HMAC_Ctx` that is set after the first `Update` call
and cleared by `Init` and `Deinit`. `Reinit` checks the flag before proceeding:

```c
// crypto/hmac/src/hmac.c — proposed fix to struct
struct HMAC_Ctx {
    CRYPT_MAC_AlgId hmacId;
    EAL_MdMethod method;
    void *mdCtx;
    void *oCtx;
    void *iCtx;
    bool hasData;    // ← ADD: set true on first Update, cleared by Init/Deinit
};

// proposed fix to Reinit
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL ||
        ctx->mdCtx == NULL || ctx->iCtx == NULL ||
        !ctx->hasData) {                             // ← ADD check
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    ctx->hasData = false;                            // ← RESET for next round
    return CRYPT_SUCCESS;
}
```

---

## Affected Files

| File | Lines | Bug |
|------|-------|-----|
| `crypto/hmac/src/hmac.c` | 236–244 | BUG-HMAC-1: `Deinit` does not null sub-context pointers |
| `crypto/hmac/src/hmac.c` | 226–234 | BUG-HMAC-2: `Reinit` lacks state check |

---

## How to Reproduce Both Bugs

```bash
# From the repository root
cd testcode/script

bash build_sdv.sh run-tests=test_suite_sdv_hmac_internal
bash execute_sdv.sh test_suite_sdv_hmac_internal
```

Expected failing tests:
```
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001  CRYPT_MAC_HMAC_SHA256  ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001  CRYPT_MAC_HMAC_SHA512  ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001  CRYPT_MAC_HMAC_SHA1    ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001  CRYPT_MAC_HMAC_SHA256  ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001  CRYPT_MAC_HMAC_SHA512  ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001  CRYPT_MAC_HMAC_SHA1    ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001    CRYPT_MAC_HMAC_SHA256  ← BUG-HMAC-2
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001    CRYPT_MAC_HMAC_SHA512  ← BUG-HMAC-2
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001    CRYPT_MAC_HMAC_SHA1    ← BUG-HMAC-2
```

---

## Additional Note: DRBG Internal API Issues

Property-based testing of the internal DRBG API revealed additional issues in
`crypto/drbg/src/drbg.c`:

- **`DRBG_Generate` does not validate `out == NULL`** when `outLen > 0` (line 325–368).
  Only `adin` is null-checked; passing `NULL, 64` bypasses the EAL wrapper and may crash.
- **`DRBG_Generate` on UNINITIALISED state auto-recovers** via `DRBG_Restart` (line 343–347),
  silently re-instantiating instead of returning `CRYPT_DRBG_ERR_STATE`. This violates
  NIST SP 800-90A §9.3.
- **`DRBG_Generate` with `outLen=0` still increments `reseedCtr`** (line 365), causing
  premature reseed triggers.

These are tracked in `testcode/sdv/testcase/crypto/drbg/test_suite_sdv_drbg_internal.c`.
