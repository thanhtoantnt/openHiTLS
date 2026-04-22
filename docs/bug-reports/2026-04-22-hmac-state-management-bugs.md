# Bug Report: openHiTLS HMAC Internal API — Three State Management Defects

**Date:** 2026-04-22  
**Component:** `crypto/hmac/src/hmac.c`  
**Discovered via:** Property-based testing with reference model automaton  
**Severity:** High — silent incorrect output and post-deinit use-after-clear

---

## Summary

Property-based testing of the internal HMAC API (`CRYPT_HMAC_*`) revealed three distinct state-management bugs:

| ID | Function | Symptom |
|----|----------|---------|
| BUG-HMAC-1 | `CRYPT_HMAC_Deinit` + `CRYPT_HMAC_Update` | Update succeeds after Deinit — should fail |
| BUG-HMAC-2 | `CRYPT_HMAC_Deinit` + `CRYPT_HMAC_Reinit` + `CRYPT_HMAC_Final` | Final succeeds after Deinit+Reinit and produces output — output is wrong |
| BUG-HMAC-3 | `CRYPT_HMAC_Reinit` from INIT state | Reinit succeeds when it should fail (called before any Update) |

All three are confirmed by running `test_suite_sdv_hmac_internal`:
```
Run 46 testcases, passed: 37, skipped: 0, failed: 9
```

---

## BUG-HMAC-1: Update Succeeds After Deinit

### Description

`CRYPT_HMAC_Deinit` calls `ctx->method.deinit` on the three internal MD contexts (`mdCtx`, `iCtx`, `oCtx`), but **does not clear the method function pointers** and **does not zero the ctx pointers** (`mdCtx`, `iCtx`, `oCtx` are still non-NULL after deinit). As a result, `CRYPT_HMAC_Update` passes its NULL-check at line 185:

```c
// crypto/hmac/src/hmac.c:183
int32_t CRYPT_HMAC_Update(CRYPT_HMAC_Ctx *ctx, const uint8_t *in, uint32_t len)
{
    if (ctx == NULL || ctx->method.update == NULL) {  // ← passes! method.update is still set
        ...
    }
    return ctx->method.update(ctx->mdCtx, in, len);  // ← calls update on deinitialized ctx
}
```

`CRYPT_HMAC_Deinit` does not null out `ctx->mdCtx` after deinit:

```c
// crypto/hmac/src/hmac.c:236
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);  // deinits but does NOT null ctx->mdCtx
    (void)ctx->method.deinit(ctx->iCtx);
    (void)ctx->method.deinit(ctx->oCtx);
    return CRYPT_SUCCESS;
}
```

### Impact

Any code that calls `CRYPT_HMAC_Update` after `CRYPT_HMAC_Deinit` will operate on deinitialized (cleared) internal state, producing **cryptographically incorrect output** without any error signal.

### Root Cause

`crypto/hmac/src/hmac.c` line 241-243: `mdCtx`, `iCtx`, `oCtx` are not nulled after `deinit`.

### Reproducer

```
SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001 CRYPT_MAC_HMAC_SHA256
```

**Test logic:**
```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out, &outLen);
CRYPT_HMAC_Deinit(mac);
int32_t ret = CRYPT_HMAC_Update(mac, msg, 64);
ASSERT_NE(ret, CRYPT_SUCCESS);  // FAILS: ret == CRYPT_SUCCESS (0)
```

**Observed:** `CRYPT_HMAC_Update` returns `CRYPT_SUCCESS` after `Deinit`.  
**Expected:** Should return an error (e.g., `CRYPT_EAL_ERR_STATE` or `CRYPT_NULL_INPUT`).

### Run to Reproduce

```bash
cd testcode/script
bash build_sdv.sh run-tests=test_suite_sdv_hmac_internal
bash execute_sdv.sh test_suite_sdv_hmac_internal
# Look for: FAIL at SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001
```

### Fix

After calling `deinit` on each sub-context in `CRYPT_HMAC_Deinit`, null the pointers:

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

With `mdCtx == NULL`, `CRYPT_HMAC_Update` will return `CRYPT_NULL_INPUT` because `ctx->method.update` is not NULL but the target context is, and the underlying hash update will catch it.

---

## BUG-HMAC-2: Final Succeeds (with Wrong Output) After Deinit+Reinit

### Description

After `CRYPT_HMAC_Deinit`, calling `CRYPT_HMAC_Reinit` **succeeds** (because `ctx->method.copyCtx` is still non-NULL). It then copies the deinitialized `iCtx` into the deinitialized `mdCtx`. A subsequent `CRYPT_HMAC_Final` also succeeds and writes output bytes — but those bytes are **cryptographically incorrect** because they are derived from cleared internal state.

### Sequence

```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out, &outLen);   // legitimate output

CRYPT_HMAC_Deinit(mac);               // clears mdCtx/iCtx/oCtx state
                                       // but does NOT null pointers or method ptrs

int32_t r = CRYPT_HMAC_Reinit(mac);   // SUCCEEDS (copyCtx != NULL)
                                       // copies zeroed iCtx → mdCtx

CRYPT_HMAC_Update(mac, msg, 64);      // SUCCEEDS (on cleared state)
int32_t f = CRYPT_HMAC_Final(mac, out2, &outLen2);  // SUCCEEDS
                                       // out2 ≠ correct HMAC output
```

### Impact

A caller that reuses a context across deinit/reinit without re-calling `Init` receives **silently wrong MAC output** with no error. This is a correctness and potential security issue — MAC verification would pass against incorrect values.

### Root Cause

Same as BUG-HMAC-1: `CRYPT_HMAC_Deinit` does not null `mdCtx`, `iCtx`, `oCtx`. Additionally, `CRYPT_HMAC_Reinit` at line 226 does not verify the context was properly initialized:

```c
// crypto/hmac/src/hmac.c:226
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL) {  // insufficient check
        ...
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);  // copies from deinitialized iCtx
    return CRYPT_SUCCESS;
}
```

### Reproducer

```
SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001 CRYPT_MAC_HMAC_SHA256
```

**Test logic:**
```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out1, &outLen1);

CRYPT_HMAC_Deinit(mac);
int32_t reinitRet = CRYPT_HMAC_Reinit(mac);   // succeeds
int32_t updateRet = CRYPT_HMAC_Update(mac, msg, 64);  // succeeds

if (reinitRet == CRYPT_SUCCESS && updateRet == CRYPT_SUCCESS) {
    int32_t finalRet = CRYPT_HMAC_Final(mac, out2, &outLen2);
    ASSERT_NE(finalRet, CRYPT_SUCCESS);  // FAILS: finalRet == CRYPT_SUCCESS (0)
    // out2 contains incorrect output
}
```

**Observed:** `CRYPT_HMAC_Final` returns `CRYPT_SUCCESS` on a deinitialized+reinit'd context.  
**Expected:** Either `Reinit` should fail after `Deinit`, or `Final` should return an error.

### Fix

Fix BUG-HMAC-1 first (null `mdCtx`/`iCtx`/`oCtx` after deinit). With those nulled, `CRYPT_HMAC_Reinit` will fail at `ctx->method.copyCtx` call because `ctx->mdCtx == NULL`, or `copyCtx` itself can be guarded:

```c
// crypto/hmac/src/hmac.c — proposed fix
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL ||
        ctx->mdCtx == NULL || ctx->iCtx == NULL) {   // ← ADD null check
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    return CRYPT_SUCCESS;
}
```

---

## BUG-HMAC-3: Reinit Succeeds from INIT State (Before Any Update)

### Description

`CRYPT_HMAC_Reinit` is documented as resetting the internal hash state back to the post-`Init` baseline. It should only be callable when in UPDATE or FINAL state (i.e., after at least one `Update` or one `Final`). However, it succeeds when called immediately after `Init` — before any `Update`.

The reference model automaton defines:
```
Reinit is valid from: UPDATE, FINAL
Reinit is INVALID from: NEW, INIT, DEINIT
```

Calling `Reinit` from INIT is idempotent (it resets the hash back to ipad, which it already is) but violates the state machine contract, confusing callers about the context's lifecycle.

### Root Cause

`CRYPT_HMAC_Reinit` has no state tracking — the internal `CRYPT_HMAC_Ctx` struct has no `state` field. It only checks that `copyCtx` is non-NULL, which is true as soon as `Init` has run:

```c
// crypto/hmac/src/hmac.c:226
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL) {  // no state check
        ...
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    return CRYPT_SUCCESS;  // always succeeds after Init
}
```

### Impact

Lower severity than BUG-1/BUG-2. The output is still correct (reinit from INIT is a no-op). However, it violates the state machine contract and makes it impossible for callers to detect incorrect usage patterns.

### Reproducer

```
SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001 CRYPT_MAC_HMAC_SHA256
```

**Test logic:**
```c
CRYPT_HMAC_Init(mac, key, 32);       // state: INIT
int32_t ret = CRYPT_HMAC_Reinit(mac); // should fail from INIT
// reference model: RefModel says Reinit from INIT returns CRYPT_EAL_ERR_STATE
if (refResult.retCode != CRYPT_SUCCESS) {
    ASSERT_NE(ret, CRYPT_SUCCESS);    // FAILS: ret == CRYPT_SUCCESS (0)
}
```

**Observed:** `CRYPT_HMAC_Reinit` returns `CRYPT_SUCCESS` immediately after `Init`.  
**Expected:** Should return `CRYPT_EAL_ERR_STATE`.

### Fix

Add a state field to `CRYPT_HMAC_Ctx` or check that `iCtx` has actually processed data. The cleanest fix is adding a `bool initialized` flag that is set after `Update` is called at least once:

```c
// crypto/hmac/src/hmac.c — proposed fix
struct HMAC_Ctx {
    CRYPT_MAC_AlgId hmacId;
    EAL_MdMethod method;
    void *mdCtx;
    void *oCtx;
    void *iCtx;
    bool hasData;    // ← ADD: true after first Update or after Reinit+Update
};
```

---

## Affected Files

| File | Lines | Bug |
|------|-------|-----|
| `crypto/hmac/src/hmac.c` | 236–244 | BUG-HMAC-1, BUG-HMAC-2: Deinit does not null sub-context pointers |
| `crypto/hmac/src/hmac.c` | 226–234 | BUG-HMAC-2, BUG-HMAC-3: Reinit lacks adequate state validation |

---

## How to Reproduce All Three Bugs

```bash
# From the repository root
cd testcode/script

# Step 1: Build
bash build_sdv.sh run-tests=test_suite_sdv_hmac_internal

# Step 2: Run
bash execute_sdv.sh test_suite_sdv_hmac_internal
```

**Expected failing tests:**
```
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001 CRYPT_MAC_HMAC_SHA256   ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001 CRYPT_MAC_HMAC_SHA512   ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_UPDATE_TC001 CRYPT_MAC_HMAC_SHA1     ← BUG-HMAC-1
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001 CRYPT_MAC_HMAC_SHA256   ← BUG-HMAC-2
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001 CRYPT_MAC_HMAC_SHA512   ← BUG-HMAC-2
FAIL: SDV_HMAC_INTERNAL_DEINIT_THEN_REINIT_TC001 CRYPT_MAC_HMAC_SHA1     ← BUG-HMAC-2
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001 CRYPT_MAC_HMAC_SHA256     ← BUG-HMAC-3
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001 CRYPT_MAC_HMAC_SHA512     ← BUG-HMAC-3
FAIL: SDV_HMAC_INTERNAL_REINIT_FROM_INIT_TC001 CRYPT_MAC_HMAC_SHA1       ← BUG-HMAC-3
```

---

## Additional Note: DRBG Internal API Issues

Property-based testing of the internal DRBG API (`DRBG_Generate`, `DRBG_Instantiate`, etc.) revealed additional issues in `crypto/drbg/src/drbg.c`:

- **`DRBG_Generate` does not validate `out == NULL`** when `outLen > 0` (line 325–368: only `adin` is checked, not `out`). Bypassing the EAL wrapper and calling with `NULL, 64` reaches `ctx->meth->generate(ctx, NULL, 64, ...)` which may crash.
- **`DRBG_Generate` on UNINITIALISED state auto-recovers** via `DRBG_Restart` (line 343–347), silently re-instantiating instead of returning `CRYPT_DRBG_ERR_STATE`. This violates NIST SP 800-90A §9.3 which requires generate to fail if the DRBG is not instantiated.
- **`DRBG_Generate` with `outLen=0` still increments `reseedCtr`** (line 365), causing premature reseed triggers.

These are tracked in `testcode/sdv/testcase/crypto/drbg/test_suite_sdv_drbg_internal.c`.
