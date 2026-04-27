# SipHash Reinit Bug — Root Cause Analysis

## Bug Summary

| Field | Value |
|-------|-------|
| **Title** | SipHash `CRYPT_EAL_MacReinit` produces wrong MAC — state registers zeroed instead of re-derived from key |
| **Severity** | HIGH — silent data corruption |
| **Type** | Logic — wrong result, no crash, no error code |
| **File** | `crypto/siphash/src/siphash.c:295-309` |
| **Discovered by** | Property-based testing: reinit equivalence property |
| **Reproduction** | `testcode/pbt/crypto/siphash/test_bug_reinit_repro.c` |

## Reproduction

```
Key:  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
Msg:  [0x00, 0x00]

Direct:  Init → Update(msg) → Final
         MAC = d0 45 03 17 23 95 6d 3a  (correct)

Reinit:  Init → Update(msg[0]) → Reinit → Update(msg) → Final
         MAC = a0 dc 66 14 9d 3d 9f 46  (WRONG)

Expected: Reinit MAC == Direct MAC
Actual:   Reinit MAC != Direct MAC
```

## Root Cause

### The Reinit Implementation (buggy)

```c
// siphash.c:295-309
int32_t CRYPT_SIPHASH_Reinit(CRYPT_SIPHASH_Ctx *ctx)
{
    ctx->state0 = 0;   // ← BUG: zeros key-derived state
    ctx->state1 = 0;   // ← BUG: zeros key-derived state
    ctx->state2 = 0;   // ← BUG: zeros key-derived state
    ctx->state3 = 0;   // ← BUG: zeros key-derived state
    ctx->accInLen = 0;
    ctx->offset = 0;
    memset(ctx->remainder, 0, SIPHASH_WORD_SIZE);
    return CRYPT_SUCCESS;
}
```

### The Init Implementation (correct)

```c
// siphash.c:186-198
uint64_t numKey0 = BytesToUint64LittleEndian(key);          // k0
uint64_t numKey1 = BytesToUint64LittleEndian(key + 8);     // k1

ctx->state0 = numKey0 ^ 0x736f6d6570736575ULL;  // k0 ⊕ magic0
ctx->state1 = numKey1 ^ 0x646f72616e646f6dULL;  // k1 ⊕ magic1
ctx->state2 = numKey0 ^ 0x6c7967656e657261ULL;  // k0 ⊕ magic2
ctx->state3 = numKey1 ^ 0x7465646279746573ULL;  // k1 ⊕ magic3
```

### What Happens Step by Step

**Direct path** (correct):
```
Init(key=[0]*16)
  → state0 = 0 ^ 0x736f6d65... = 0x736f6d6570736575
  → state1 = 0 ^ 0x646f7261... = 0x646f72616e646f6d
  → state2 = 0 ^ 0x6c796765... = 0x6c7967656e657261
  → state3 = 0 ^ 0x74656462... = 0x7465646279746573

Update([0x00, 0x00])
  → curWord = 0x0000
  → state3 ^= curWord  → state3 = 0x7465646279746573 ^ 0x0000 = unchanged
  → SipRound × 2 (compression)
  → state0 ^= curWord

Final()
  → DealLastWord: lastWord = msgLen(2) << 56 | remainder[0] | remainder[1]
     = 0x0000000000000002 | 0x00 | 0x00 = 0x0000000000000200
  → UpdateInternalState(curWord)
  → state2 ^= 0xee
  → SipRound × 4 (finalization)
  → result = state0 ^ state1 ^ state2 ^ state3 = 0x3a6d9523170345d0
```

**Reinit path** (buggy):
```
Init(key=[0]*16)
  → state = key-dependent values (same as above)

Update([0x00]) — one byte
  → curWord = 0x00
  → state3 ^= 0x00
  → SipRound × 2

Reinit()
  → state0 = 0  ← RESETS TO ZERO, LOSES KEY
  → state1 = 0  ← RESETS TO ZERO, LOSES KEY
  → state2 = 0  ← RESETS TO ZERO, LOSES KEY
  → state3 = 0  ← RESETS TO ZERO, LOSES KEY
  → accInLen = 0, offset = 0, remainder cleared

Update([0x00, 0x00])
  → curWord = 0x0000
  → state3 ^= 0x0000 = 0 ← XOR with zero (no key influence)
  → SipRound × 2
  → state0 ^= 0x0000 = 0

Final()
  → DealLastWord: 0x0000000000000200
  → UpdateInternalState starting from ALL-ZERO state
  → state2 ^= 0xee → state2 = 0xee
  → SipRound × 4
  → result = 0x469f3d9d1466dca0  ← COMPLETELY WRONG
```

### Why Reinit Can't Work

`struct SIPHASH_Ctx` does NOT store the original key:

```c
struct SIPHASH_Ctx {        // siphash.c:39-50
    uint64_t state0;         // ← key-derived, overwritten by Update
    uint64_t state1;         // ← key-derived, overwritten by Update
    uint64_t state2;         // ← key-derived, overwritten by Update
    uint64_t state3;         // ← key-derived, overwritten by Update
    uint16_t compressionRounds;
    uint16_t finalizationRounds;
    uint32_t hashSize;
    uint32_t accInLen;
    uint32_t offset;
    uint8_t  remainder[8];
    // NOTE: key is NOT stored here
};
```

Once `Update()` modifies `state0-state3` (via `SiproundOperation`), the original key-derived values are lost forever. `Reinit()` cannot restore them because:
1. The key bytes are not stored in the struct
2. The original state is not saved anywhere
3. There is no way to reverse the SipRound operations to recover the key

### Comparison: HMAC Reinit (correct)

HMAC's `CRYPT_HMAC_Reinit` works correctly because:

```c
// hmac.c:225-233
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);  // copy iCtx → mdCtx
    return CRYPT_SUCCESS;
}
```

HMAC stores THREE separate contexts (`mdCtx`, `iCtx`, `oCtx`). `Reinit` copies `iCtx` (which preserves the post-Init keyed state) back to `mdCtx`. The keyed state is always preserved in `iCtx` and `oCtx`.

SipHash has no equivalent preservation — there is only one set of state registers and no saved copy.

## Fix

### Option A: Store the key (recommended)

```c
struct SIPHASH_Ctx {
    uint64_t state0, state1, state2, state3;
    uint8_t  key[16];  // ← ADD: store original key
    // ... rest unchanged ...
};

int32_t CRYPT_SIPHASH_Init(CRYPT_SIPHASH_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    // ... existing validation ...
    memcpy(ctx->key, key, 16);  // ← ADD: save key
    // ... existing state initialization from key ...
}

int32_t CRYPT_SIPHASH_Reinit(CRYPT_SIPHASH_Ctx *ctx)
{
    // Re-derive state from stored key (same as Init)
    uint64_t k0 = BytesToUint64LittleEndian(ctx->key);
    uint64_t k1 = BytesToUint64LittleEndian(ctx->key + 8);
    ctx->state0 = k0 ^ 0x736f6d6570736575ULL;
    ctx->state1 = k1 ^ 0x646f72616e646f6dULL;
    ctx->state2 = k0 ^ 0x6c7967656e657261ULL;
    ctx->state3 = k1 ^ 0x7465646279746573ULL;
    if (ctx->hashSize == SIPHASH_MAX_DIGEST_SIZE) ctx->state1 ^= 0xee;
    ctx->accInLen = 0;
    ctx->offset = 0;
    memset(ctx->remainder, 0, SIPHASH_WORD_SIZE);
    return CRYPT_SUCCESS;
}
```

### Option B: Save initial state instead of key

```c
struct SIPHASH_Ctx {
    uint64_t state0, state1, state2, state3;
    uint64_t initState0, initState1, initState2, initState3;  // ← save initial values
    // ... rest unchanged ...
};

// In Init: save initial state
ctx->initState0 = ctx->state0;
ctx->initState1 = ctx->state1;
ctx->initState2 = ctx->state2;
ctx->initState3 = ctx->state3;

// In Reinit: restore from saved initial state
ctx->state0 = ctx->initState0;
ctx->state1 = ctx->initState1;
ctx->state2 = ctx->initState2;
ctx->state3 = ctx->initState3;
```

### Impact on DupCtx

`CRYPT_SIPHASH_DupCtx` uses `BSL_SAL_Dump` (memcpy of the entire struct), so if the fix adds a `key[16]` or `initState*` fields, `DupCtx` will automatically copy them. No change needed to `DupCtx`.

## Why This Property Was Tested

The property comes from the code's own documented behavior, not from speculation. Three pieces of evidence form the chain:

### 1. The Code's Docstring Claim

`crypto/siphash/include/crypt_siphash.h`, the function declaration for `CRYPT_SIPHASH_Reinit`:

> *Re-initialize using the information retained in the ctx. Do not need to invoke the init again. **This function is equivalent to the combination of deinit and init interfaces.***

The API explicitly claims equivalence: `Reinit ≡ Deinit + Init`. The property tests exactly that:

```
Direct:  Init → Update(msg) → Final
Reinit:  Init → Update(partial) → Reinit → Update(msg) → Final
```

If the outputs differ, the docstring's claim is false — `Reinit` is NOT equivalent to `Deinit + Init`.

### 2. The PBT Skill's Property Discovery Rule

From `building-property-based-tests/04-discover-properties.md`, "Additional Properties for Approach B":

> | **Equivalence** | Two operation sequences that should produce the same result do — e.g. `reinit` equals fresh `init` with same key |

This rule was hardened in changelog v2 after earlier PBT runs on HMAC and CMAC found that agents were skipping Reinit tests entirely — writing valid-sequence tests but never testing the functions the API actually exposes.

### 3. The Skill's Grounding Rule

From `building-property-based-tests/building-property-based-tests.md`, Golden Rules:

> *Only test properties the code explicitly claims. Evidence comes from docstrings, type annotations, comments, existing tests, and how callers use the function. Invented properties produce false alarms and waste time.*

The docstring **is** the evidence. The equivalence property **is** the test of that evidence. The approach is: read what the code promises → write a test that verifies the promise holds. When it doesn't, the code is broken, not the test.

## The Property Test That Caught the Bug

From `testcode/pbt/crypto/siphash/test_pbt_siphash.cpp`:

```cpp
// Approach B: Reinit equivalence property
// Grounded in: crypt_siphash.h docstring — "equivalent to deinit + init"
// Property type: Equivalence (from 04-discover-properties.md)

run("Reinit equivalence", [](const Key &k, const std::vector<uint8_t> &m) {
    RC_PRE(m.size() >= 2);

    // Reference: Init → Update(full message) → Final
    auto ref = sip(k, m);

    // Reinit path: Init → Update(1 byte) → Reinit → Update(full msg) → Final
    CRYPT_EAL_MacCtx *c = CRYPT_EAL_MacNewCtx(kSipHashAlg);
    RC_ASSERT(CRYPT_EAL_MacInit(c, k.data(), 16) == CRYPT_SUCCESS);
    RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), 1) == CRYPT_SUCCESS);
    RC_ASSERT(CRYPT_EAL_MacReinit(c) == CRYPT_SUCCESS);
    RC_ASSERT(CRYPT_EAL_MacUpdate(c, m.data(), m.size()) == CRYPT_SUCCESS);
    uint32_t l = 8; std::vector<uint8_t> rmac(l);
    RC_ASSERT(CRYPT_EAL_MacFinal(c, rmac.data(), &l) == CRYPT_SUCCESS);
    rmac.resize(l);
    CRYPT_EAL_MacFreeCtx(c);

    RC_ASSERT(rmac == ref);  // ← FAILED: MACs differ — docstring violated
});
```

rapidcheck generated 100 random (key, message) pairs. The property failed on the very first test — the all-zero key with the two-byte zero message. The framework automatically shrunk the counterexample to this minimal reproduction case.

## Why Manual Review Missed This

A manual review would likely not catch this bug because:

1. **No crash, no error code** — `CRYPT_SIPHASH_Reinit` returns `CRYPT_SUCCESS`. There's no visible failure.
2. **The state registers are private** — `state0-state3` are internal `uint64_t` fields in the opaque `struct SIPHASH_Ctx`. A reviewer reading `Reinit()` sees `state*=0` and thinks "resetting state" is correct.
3. **The comparison requires calling another function** — you can't tell `Reinit` is broken by looking at it in isolation. You need to follow it with `Update` + `Final` and compare the output against the direct path. Property-based testing does this automatically.

The only way to catch this bug is to verify the docstring's claim — which is exactly what the equivalence property does.
