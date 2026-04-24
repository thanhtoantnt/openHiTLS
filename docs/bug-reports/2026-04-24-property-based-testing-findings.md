# openHiTLS Property-Based Testing — Bug Report

**Date:** 2026-04-24
**Discovered by:** Property-based testing with reference model automata
**Method:** Random operation sequences applied to both implementation and reference model;
            state and output discrepancies flagged as failures.

---

## Executive Summary

This session extended property-based testing to two additional components: CMAC/CBCMAC
and the EAL cipher layer (GCM). Two new confirmed bugs were found.

The HMAC bugs found in this session are already documented in
[`2026-04-22-hmac-state-management-bugs.md`](./2026-04-22-hmac-state-management-bugs.md)
(BUG-HMAC-1 and BUG-HMAC-2). They are not repeated here.

| ID | Component | Severity | Class | Status |
|----|-----------|----------|-------|--------|
| BUG-001 | `CipherMacReinit` (CMAC/CBCMAC) | **Medium** | Invalid state transition accepted | Confirmed |
| BUG-002 | `CRYPT_EAL_CipherCtrl` (GCM) | **Medium** | AEAD tag readable before Final | Confirmed |

---

## Methodology

Each bug was discovered by the following process:

1. **Reference model** — A minimal state machine was written that encodes the documented
   API contract for each component: which operations are legal in which states, and what
   state each operation should produce.

2. **Property-based test** — Random sequences of operations were generated and applied to
   both the implementation and the reference model. After each operation, the test checks:
   - If the reference model predicts success, the implementation must return `CRYPT_SUCCESS`.
   - If the reference model predicts failure, the implementation must return a non-zero
     error code.

3. **Bug confirmation** — Every failure was verified with a minimal fixed-input reproducer
   that does not require the property-based test framework.

---

## BUG-001 — CMAC/CBCMAC: `CipherMacReinit` Has No State Validation

### Severity: Medium

### Location

```
crypto/cmac/src/cipher_mac_common.c:130–140  (CipherMacReinit)
```

Affects: `CRYPT_CMAC_Reinit`, and any other MAC algorithm that uses
`CipherMacReinit` (currently CMAC and CBCMAC share this implementation).

### Root Cause

`CipherMacReinit` is the shared reinit implementation for cipher-based MACs.
It only validates that `ctx != NULL`, with no tracking of whether the context
has processed any data:

```c
// crypto/cmac/src/cipher_mac_common.c:130 — BUG
int32_t CipherMacReinit(Cipher_MAC_Common_Ctx *ctx)
{
    if (ctx == NULL) {                   // only null check — no state check
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memset_s(ctx->data, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    ctx->len = 0;
    return CRYPT_SUCCESS;               // always succeeds after Init
}
```

The `Cipher_MAC_Common_Ctx` struct has no `state` field. It tracks only `len`
(bytes buffered, 0 to blockSize-1). When `len == 0` after `Init` and before
any `Update`, calling `Reinit` is indistinguishable from a valid `Reinit` after
`Final`. The call always succeeds.

### Impact

`Reinit` from NEW or INIT state (before any data) succeeds without error, violating
the state machine contract for both CMAC and CBCMAC. Output remains correct (the
no-op reinit is harmless for the cipher state), but incorrect usage cannot be
detected by the caller.

This is the same class of defect as BUG-HMAC-2 in the HMAC component — no state
tracking means the API cannot enforce its own lifecycle contract.

### Reference Model State Machine

```
Reinit is valid from:   UPDATE, FINAL
Reinit is invalid from: NEW, INIT
```

### Reproducer

```c
// Test: SDV_CMAC_STATE_MACHINE_REINIT_FROM_INIT_TC001
// Via EAL: CRYPT_EAL_MacReinit maps to CipherMacReinit for CMAC

CRYPT_EAL_MacInit(mac, key, 16);   // state: INIT (no data processed)

int32_t ret = CRYPT_EAL_MacReinit(mac);
// Reference model: INIT → ERR_STATE
// Expected: CRYPT_EAL_ERR_STATE
// Actual:   CRYPT_SUCCESS
```

### Run to Reproduce

```bash
cd testcode/script
bash build_sdv.sh run-tests=test_suite_sdv_cmac_statemachine
bash execute_sdv.sh test_suite_sdv_cmac_statemachine
# Failing: SDV_CMAC_STATE_MACHINE_REINIT_FROM_INIT_TC001  (AES-128, AES-256)
```

### Fix

Add a `hasData` boolean to `Cipher_MAC_Common_Ctx`. Set it in `CipherMacUpdate`,
clear it in `CipherMacInit` and `CipherMacDeinit`. Check it in `CipherMacReinit`:

```c
// Proposed fix — cipher_mac_common.h struct
struct Cipher_MAC_Common_Ctx {
    const EAL_SymMethod *method;
    void    *key;
    uint8_t  data[CIPHER_MAC_MAXBLOCKSIZE];
    uint8_t  left[CIPHER_MAC_MAXBLOCKSIZE];
    uint32_t len;
    bool     hasData;    // ← ADD
};

// Proposed fix — CipherMacReinit
int32_t CipherMacReinit(Cipher_MAC_Common_Ctx *ctx)
{
    if (ctx == NULL || !ctx->hasData) {   // ← ADD state check
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    (void)memset_s(ctx->data, CIPHER_MAC_MAXBLOCKSIZE, 0, CIPHER_MAC_MAXBLOCKSIZE);
    ctx->len = 0;
    ctx->hasData = false;                 // ← RESET
    return CRYPT_SUCCESS;
}
```

---

## BUG-002 — GCM: `GET_TAG` Returns Incomplete Tag Before `Final`

### Severity: Medium

### Location

```
crypto/eal/src/eal_cipher.c:287–304  (CipherCtrlIsCanSet)
crypto/eal/src/eal_cipher.c:306–337  (CRYPT_EAL_CipherCtrl)
```

Affects: All AEAD cipher modes that support `CRYPT_CTRL_GET_TAG` (GCM, CCM).

### Root Cause

`CipherCtrlIsCanSet` decides which control operations are permitted in each
cipher state. It contains an early-return that unconditionally allows `GET_TAG`
from any non-NEW state:

```c
// crypto/eal/src/eal_cipher.c:287 — BUG
static bool CipherCtrlIsCanSet(const CRYPT_EAL_CipherCtx *ctx, int32_t type)
{
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        return false;
    }
    if (type == CRYPT_CTRL_GET_TAG) {
        return true;             // ← BUG: allows GET_TAG from INIT and UPDATE
    }
    if (ctx->states == EAL_CIPHER_STATE_FINAL) {
        return false;
    }
    // ... other checks ...
    return true;
}
```

The `GET_TAG` early-return fires before the `FINAL` state check, so `GET_TAG`
is permitted from INIT and UPDATE states as well as from FINAL. The correct
behavior is that `GET_TAG` should only succeed after `Final` has been called —
only then is the AEAD authentication tag fully computed over all ciphertext.

### Impact

A caller can retrieve the GCM authentication tag before calling `Final`, receiving
a **partial or zeroed tag** with no error indication. Because the tag is computed
progressively during `Final`, the value returned by `GET_TAG` from INIT or UPDATE
state is an unfinished computation — not a valid AEAD authentication tag.

Consequences:
- In a TLS or application layer using GCM, early tag retrieval and use for message
  authentication would cause authentication to succeed on incomplete or modified
  ciphertext.
- The caller receives no indication that the tag is invalid; `CRYPT_SUCCESS` is
  returned.

### Reference Model State Machine

```
GET_TAG is valid from:   FINAL only
GET_TAG is invalid from: NEW, INIT, UPDATE
```

### Reproducer

```c
// Test: SDV_CIPHER_STATE_MACHINE_AEAD_TAG_STATE_TC001

CRYPT_EAL_CipherInit(ctx, key, 32, iv, 12, true);  // state: INIT

uint8_t tag[16];
int32_t ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, tag, 16);
// Reference model: INIT → GET_TAG → ERR_STATE
// Expected: CRYPT_EAL_ERR_STATE
// Actual:   CRYPT_SUCCESS — tag[] contains meaningless data
```

### Run to Reproduce

```bash
cd testcode/script
bash build_sdv.sh run-tests=test_suite_sdv_cipher_statemachine
bash execute_sdv.sh test_suite_sdv_cipher_statemachine
# Failing: SDV_CIPHER_STATE_MACHINE_AEAD_TAG_STATE_TC001
#          CRYPT_CIPHER_AES256_GCM, CRYPT_CIPHER_AES128_GCM
```

### Fix

Move the `GET_TAG` check to after the `FINAL` state check so it is only permitted
when the cipher has completed its operation:

```c
// Proposed fix — crypto/eal/src/eal_cipher.c:287
static bool CipherCtrlIsCanSet(const CRYPT_EAL_CipherCtx *ctx, int32_t type)
{
    if (ctx->states == EAL_CIPHER_STATE_NEW) {
        return false;
    }
    // Remove early GET_TAG return; let FINAL check apply first
    if (ctx->states == EAL_CIPHER_STATE_FINAL) {
        if (type == CRYPT_CTRL_GET_TAG) {
            return true;         // ← GET_TAG only valid from FINAL
        }
        return false;
    }
    if ((ctx->states == EAL_CIPHER_STATE_UPDATE) &&
        (type == CRYPT_CTRL_SET_COUNT || type == CRYPT_CTRL_SET_TAGLEN ||
         type == CRYPT_CTRL_SET_MSGLEN || type == CRYPT_CTRL_SET_AAD)) {
        return false;
    }
    return true;
}
```

---

## Test Coverage Summary

| Suite | Tests | Pass | Fail | Bugs Covered |
|-------|-------|------|------|--------------|
| `test_suite_sdv_hmac_internal` | 46 | 37 | 9 | See [2026-04-22 report](./2026-04-22-hmac-state-management-bugs.md) |
| `test_suite_sdv_cmac_statemachine` | 23 | 21 | **2** | BUG-001 (2) |
| `test_suite_sdv_cipher_statemachine` | 29 | 27 | **2** | BUG-002 (2) |

All other test suites (DRBG, HMAC EAL, MD, RSA, CBC, HKDF, ECDSA) pass 100%.

---

## Affected Files

| File | Lines | Bug |
|------|-------|-----|
| `crypto/cmac/src/cipher_mac_common.c` | 130–140 | BUG-001: `CipherMacReinit` has no state check |
| `crypto/eal/src/eal_cipher.c` | 287–304 | BUG-002: `GET_TAG` allowed before `Final` |

---

## How to Reproduce

```bash
cd testcode/script

bash build_sdv.sh run-tests=test_suite_sdv_cmac_statemachine
bash execute_sdv.sh test_suite_sdv_cmac_statemachine    # BUG-003

bash build_sdv.sh run-tests=test_suite_sdv_cipher_statemachine
bash execute_sdv.sh test_suite_sdv_cipher_statemachine  # BUG-004
```

Expected output:
```
test_suite_sdv_cmac_statemachine...  FAIL  (2 failed: REINIT_FROM_INIT x2)
test_suite_sdv_cipher_statemachine.  FAIL  (2 failed: AEAD_TAG_STATE x2)
```
