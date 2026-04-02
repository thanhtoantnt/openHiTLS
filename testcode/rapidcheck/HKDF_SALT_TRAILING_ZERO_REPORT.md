# HKDF Salt Trailing Zero — PBT Finding Report

## Summary

**Status**: Correct implementation behavior (NOT a bug).  
**Finding**: HKDF with salt `[0x01, 0x00]` produces the same output as HKDF with salt
`[0x01]`. The outputs are identical by requirement of RFC 5869 and RFC 2104.  
**Test added**: `SDV_CRYPTO_HKDF_SALT_TRAILING_ZERO_PBT_TC001`

---

## Concrete Counterexample (from RapidCheck seed=1)

```
Algorithm : HKDF-SHA1 (CRYPT_MAC_HMAC_SHA1)
IKM       : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  (16 zero bytes)
salt1     : 01 00                                             (2 bytes)
salt2     : 01                                                (1 byte)
info      : (empty)
OKM length: 20 bytes

Result with salt1 : ba 4a f4 f0 8b 6b bb 2e 92 45 8f 51 ff c3 34 5d de 34 0b 1e
Result with salt2 : ba 4a f4 f0 8b 6b bb 2e 92 45 8f 51 ff c3 34 5d de 34 0b 1e
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                    IDENTICAL  — this is the correct, RFC-mandated result
```

Reproduction:
```bash
cd testcode/rapidcheck/build
RC_PARAMS="seed=1" ./rapidcheck_kdf_test salt_sensitivity
```

---

## Root Cause Analysis

### Step 1: HKDF Extract (RFC 5869 §2.2)

The HKDF Extract step is defined as:

```
HKDF-Extract(salt, IKM) -> PRK
PRK = HMAC-Hash(salt, IKM)
```

The salt is passed directly as the **HMAC key** (`hkdf.c:100`):

```c
// crypto/hkdf/src/hkdf.c, line 100
GOTO_ERR_IF(macMeth->init(macCtx, salt, saltLen, NULL), ret);
```

### Step 2: HMAC Key Zero-Padding (RFC 2104 §2)

RFC 2104 defines key preprocessing for HMAC:

> "If the length of K = B: set K0 = K.  
> If the length of K < B: **append zeros** to the end of K to create a B-byte string K0."

For HMAC-SHA1, the block size B = **64 bytes**.

| Salt value      | Length | Zero-padded to 64 bytes                         |
|-----------------|--------|-------------------------------------------------|
| `[0x01, 0x00]`  | 2      | `[0x01, 0x00, 0x00, 0x00, ..., 0x00]` (64 bytes) |
| `[0x01]`        | 1      | `[0x01, 0x00, 0x00, 0x00, ..., 0x00]` (64 bytes) |

Both produce **bit-for-bit identical** HMAC key pads. The trailing `0x00` byte in
`salt1` is invisible after zero-padding.

### Step 3: Identical PRK and OKM

Because the HMAC inner and outer pads are identical, the Extract step produces the
same PRK for both salts. The Expand step is deterministic given PRK, so the final OKM
is the same.

### Implementation Trace (`crypto/hkdf/src/hkdf.c`)

```c
// Extract — salt becomes the HMAC key
int32_t CRYPT_HKDF_Extract(..., const uint8_t *salt, uint32_t saltLen, ...) {
    (void)macMeth->deinit(macCtx);
    GOTO_ERR_IF(macMeth->init(macCtx, salt, saltLen, NULL), ret);  // salt → HMAC key
    GOTO_ERR_IF(macMeth->update(macCtx, key, keyLen), ret);         // key  → HMAC data
    GOTO_ERR_IF(macMeth->final(macCtx, prk, prkLen), ret);
    ...
}
```

Inside HMAC init (`crypto/hmac/src/hmac.c`):
```c
// Keys shorter than blockSize are zero-padded (RFC 2104 §2)
for (i = 0; i < keyLen; i++) {
    ipad[i] = 0x36 ^ keyTmp[i];
    opad[i] = 0x5c ^ keyTmp[i];
}
for (i = keyLen; i < ctx->method.blockSize; i++) {
    ipad[i] = 0x36;   // 0x36 ^ 0x00 (implicit zero pad)
    opad[i] = 0x5c;   // 0x5c ^ 0x00
}
```

Trace for `salt1 = [0x01, 0x00]` (keyLen=2, blockSize=64):
```
Loop i=0: ipad[0] = 0x36 ^ 0x01 = 0x37
Loop i=1: ipad[1] = 0x36 ^ 0x00 = 0x36
Loop i=2..63: ipad[i] = 0x36
Final ipad: [0x37, 0x36, 0x36, ..., 0x36]
```

Trace for `salt2 = [0x01]` (keyLen=1, blockSize=64):
```
Loop i=0: ipad[0] = 0x36 ^ 0x01 = 0x37
Loop i=1..63: ipad[i] = 0x36
Final ipad: [0x37, 0x36, 0x36, ..., 0x36]
```

**Result: ipad is identical in both cases. The implementation is correct.**

---

## Why The PBT Property Was Initially Failing

The original PBT property was:

```cpp
// WRONG: too strong
RC_ASSERT(derive(salt1) != derive(salt2));  // fails when salt1 != salt2 byte-wise
                                             // but are zero-padding equivalent
```

This fails for any pair where:
- salt1 and salt2 differ only in trailing zero bytes, AND
- both are shorter than the HMAC block size (64 bytes for SHA-1/SHA-256)

The property was corrected to exclude zero-padding-equivalent pairs:

```cpp
// CORRECT: exclude all-zero-content pairs that differ only in length
bool s1AllZero = std::all_of(salt1.begin(), salt1.end(), [](uint8_t b){ return b == 0; });
bool s2AllZero = std::all_of(salt2.begin(), salt2.end(), [](uint8_t b){ return b == 0; });
RC_PRE(!(s1AllZero && s2AllZero));
```

This correctly handles the all-zero case but **still misses the exact counterexample**
`[0x01, 0x00]` vs `[0x01]`, where only one byte is non-zero and the trailing zero
makes the salts zero-padding-equivalent.

The **correct general condition** for two salts to be guaranteed to produce different
OKMs is:

```
zero_pad(salt1, blockSize) != zero_pad(salt2, blockSize)
```

The corrected PBT property should pre-filter by this condition, not just the
"all-zero" check. This is why the test still occasionally fails with seed-dependent
inputs like the seed=1 case.

---

## Classification

| Attribute        | Value                                                  |
|------------------|--------------------------------------------------------|
| Finding type     | **Overly-strong PBT property** (not a code bug)        |
| Standard         | RFC 5869 (HKDF), RFC 2104 (HMAC)                       |
| Affected algos   | All HKDF algorithms (SHA-1, SHA-2, SM3)                |
| Implementation   | openHiTLS is correct                                   |
| Analogous issue  | Same root cause as HMAC key-sensitivity PBT failure    |

---

## Unit Test Added

**File**: `testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.c`  
**Name**: `SDV_CRYPTO_HKDF_SALT_TRAILING_ZERO_PBT_TC001`

The test **asserts equality** (`output1 == output2`) — documenting that the behavior
is correct and serving as a regression test to ensure the implementation continues
to follow RFC 5869 + RFC 2104.

---

## Correct Fix: Strengthen the PBT Guard

The PBT property in `rapidcheck_kdf_test.cpp` should be updated to exclude all
zero-padding-equivalent salt pairs, not just all-zero pairs:

```cpp
// Helper: compute the effective HMAC key after zero-padding to blockSize
auto zeroPad = [](const std::vector<uint8_t> &v, size_t blockSize) {
    std::vector<uint8_t> padded(blockSize, 0);
    for (size_t i = 0; i < v.size() && i < blockSize; i++) padded[i] = v[i];
    return padded;
};

// Only test pairs that are NOT zero-padding equivalent
// (64 is the minimum block size across all supported HKDF algorithms)
RC_PRE(zeroPad(salt1, 64) != zeroPad(salt2, 64));
```

This properly models the RFC constraint and eliminates all false positives.
