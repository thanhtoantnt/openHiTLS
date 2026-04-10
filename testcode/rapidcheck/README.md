# RapidCheck Property-Based Tests for openHiTLS

This directory contains property-based tests for openHiTLS using the [RapidCheck](https://github.com/emil-e/rapidcheck) framework.

Each test file includes annotations linking to the original unit tests that the property-based tests generalize. Look for `@generalizes` and `@see` tags in the source code.

## IMPORTANT: Test Public APIs Only

**DO NOT test internal functions directly.** openHiTLS uses a layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  PUBLIC API (Test These)                                    │
│  CRYPT_EAL_CipherUpdate, CRYPT_EAL_MdUpdate, etc.           │
│  ✓ Has input validation                                     │
│  ✓ Returns error codes for invalid inputs                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  INTERNAL API (Do NOT Test Directly)                        │
│  CRYPT_AES_Encrypt, CRYPT_SM3_Update, etc.                  │
│  ✗ No input validation (assumes upper layer validated)      │
│  ✗ May crash on NULL inputs (by design)                     │
└─────────────────────────────────────────────────────────────┘
```

### Public vs Internal API

| Public API (Test These) | Internal API (Do NOT Test) |
|------------------------|---------------------------|
| `CRYPT_EAL_CipherNewCtx` | `CRYPT_AES_Encrypt` |
| `CRYPT_EAL_CipherInit` | `CRYPT_AES_Decrypt` |
| `CRYPT_EAL_CipherUpdate` | `CRYPT_SM3_Update` |
| `CRYPT_EAL_CipherFinal` | `CRYPT_SM3_Final` |
| `CRYPT_EAL_MdNewCtx` | `CRYPT_AES_SetEncryptKey128` |
| `CRYPT_EAL_MdUpdate` | Internal helper functions |
| `CRYPT_EAL_MdFinal` | |

### Why Not Test Internal APIs

1. **They assume validated inputs** - Upper layers already validated
2. **No error handling overhead** - Performance optimization for crypto
3. **Testing them directly is testing implementation details**
4. **May crash on NULL - this is expected, not a bug**

## What is Property-Based Testing?

Property-based testing is a testing methodology where you define **properties** (invariants) that should always hold true for your code, rather than writing specific test cases with fixed inputs. The testing framework then automatically generates random test inputs to try to find cases where the property fails.

Key benefits:
- **Automatic test case generation**: Tests thousands of random inputs automatically
- **Shrinking**: When a failure is found, RapidCheck automatically finds the minimal failing case
- **Better coverage**: Finds edge cases you might not think of manually

## Test Files

| File | Description |
|------|-------------|
| `rapidcheck_aes_test.cpp` | Property tests for AES encryption/decryption |
| `rapidcheck_hash_test.cpp` | Property tests for SM3 hash functions |
| `rapidcheck_hmac_test.cpp` | Property tests for HMAC operations |

## Properties Tested

### AES Tests (7 properties)
Each property generalizes specific unit tests from `testcode/sdv/testcase/crypto/aes/`:

| Property | Generalizes | Unit Test File |
|----------|-------------|----------------|
| Encrypt-decrypt roundtrip (128/192/256-bit) | `SDV_CRYPTO_AES_INIT_API_TC001`, `SDV_CRYPTO_AES_ENCRYPT_DECRYPT_API_TC001` | `test_suite_sdv_eal_aes.c` |
| Different plaintexts → different ciphertexts | Confusion property | `test_suite_sdv_eal_aes.c` |
| Different keys → different ciphertexts | Key sensitivity | `test_suite_sdv_eal_aes.c` |
| Deterministic encryption | `SDV_CRYPTO_AES_ENCRYPT_DECRYPT_API_TC001` | `test_suite_sdv_eal_aes.c:574` |
| Ciphertext differs from plaintext | Confusion property | `test_suite_sdv_eal_aes.c` |

### Hash Tests (SM3) (5 properties)
Each property generalizes specific unit tests from `testcode/sdv/testcase/crypto/sm3/`:

| Property | Generalizes | Unit Test File |
|----------|-------------|----------------|
| Determinism | `SDV_CRYPT_EAL_SM3_API_TC001`, `MultiThreadTest` | `test_suite_sdv_eal_sm3.c:33-50, 72-114` |
| Fixed 32-byte output | `SDV_CRYPT_EAL_SM3_API_TC001` | `test_suite_sdv_eal_sm3.c:77-82` |
| Incremental hashing | `SDV_CRYPT_EAL_SM3_API_TC003`, `SDV_CRYPT_EAL_SM3_API_TC004` | `test_suite_sdv_eal_sm3.c:200-236, 270-295` |
| Different inputs → different hashes | Collision resistance | `test_suite_sdv_eal_sm3.c` |
| Context copy produces same hash | `SDV_CRYPT_EAL_SM3_API_TC005` | `test_suite_sdv_eal_sm3.c:312-360` |

### HMAC Tests (7 properties) - Currently Disabled
Each property generalizes specific unit tests from `testcode/sdv/testcase/crypto/hmac/`:

| Property | Generalizes | Unit Test File |
|----------|-------------|----------------|
| Determinism | `SDV_CRYPT_EAL_HMAC_API_TC001`, `SDV_CRYPT_EAL_HMAC_API_TC002` | `test_suite_sdv_eal_mac_hmac.c:34-88` |
| Output size matches expected | `SDV_CRYPT_EAL_HMAC_API_TC002` | `test_suite_sdv_eal_mac_hmac.c:73-88` |
| Incremental update | `SDV_CRYPT_EAL_HMAC_API_TC003` | `test_suite_sdv_eal_mac_hmac.c:100-150` |
| Key sensitivity | Key sensitivity test | `test_suite_sdv_eal_mac_hmac.c` |
| Message sensitivity | Message sensitivity test | `test_suite_sdv_eal_mac_hmac.c` |
| Reinit produces same MAC | `SDV_CRYPT_EAL_HMAC_API_TC003` | `test_suite_sdv_eal_mac_hmac.c:100-130` |
| Context duplication | `SDV_CRYPT_EAL_HMAC_API_TC004` | `test_suite_sdv_eal_mac_hmac.c` |

**Note**: HMAC tests are disabled due to C++ keyword conflict (`export` used as struct member in `crypt_local_types.h:207`).

## Building the Tests

### Prerequisites
- CMake 3.16+
- C++17 compiler
- openHiTLS built with crypto components

### Build Steps

```bash
# 1. Build openHiTLS first
cd /path/to/openHiTLS
mkdir -p build && cd build
python3 ../configure.py --enable hitls_bsl hitls_crypto --lib_type static --bits=64 --system=linux
cmake .. && make

# 2. Build RapidCheck tests
cd testcode/rapidcheck
mkdir -p build && cd build
cmake .. -DopenHiTLS_SRC=/path/to/openHiTLS
make

# 3. Run tests
./rapidcheck_aes_test
./rapidcheck_hash_test
./rapidcheck_hmac_test

# Or run all tests via CTest
ctest
```

## Example Output

When tests pass:
```
Using configuration: seed=1234567890

- AES ECB encrypt-decrypt roundtrip preserves plaintext
OK, passed 100 tests

- AES single block encrypt-decrypt roundtrip
OK, passed 100 tests
```

When a test fails (hypothetical bug):
```
Falsifiable after 12 tests and 10 shrinks

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>:
([1, 0, 0, 0], [16 byte key])

rapidcheck_aes_test.cpp:45:
RC_ASSERT(plaintext == decrypted)

Expands to:
[1, 0, 0, 0] == [0, 0, 0, 0]
```

## Writing New Property Tests

### Basic Pattern

```cpp
#include <rapidcheck.h>
#include "your_header.h"

using namespace rc;

int main() {
    rc::check("Property description",
        [](const std::vector<uint8_t> &input) {
            // Preconditions (filter inputs)
            RC_PRE(input.size() > 0);
            
            // Call function under test
            auto result = your_function(input);
            
            // Assert property
            RC_ASSERT(result.size() == expected_size);
        });
    
    return 0;
}
```

### Key Macros

| Macro | Purpose |
|-------|---------|
| `RC_PRE(condition)` | Precondition - skip test if false |
| `RC_ASSERT(condition)` | Assert property must hold |
| `RC_LOG(msg)` | Log debug information |
| `RC_FAIL(msg)` | Explicitly fail the test |

### Generators

```cpp
// Built-in types
gen::arbitrary<int>()
gen::arbitrary<uint8_t>()

// Collections
gen::vectorOf(gen::arbitrary<uint8_t>())       // Random size
gen::vectorOfN(16, gen::arbitrary<uint8_t>())  // Fixed size

// Ranges
gen::inRange(0, 100)                           // Integer in [0, 100)

// Combinations
gen::pair(gen::arbitrary<int>(), gen::arbitrary<int>())
gen::map(gen::arbitrary<int>(), [](int x) { return x * 2; })
```

### Custom Generators

```cpp
namespace rc {

template<>
struct Arbitrary<YourType> {
    static Gen<YourType> arbitrary() {
        return gen::map(
            gen::vectorOfN(32, gen::arbitrary<uint8_t>()),
            [](const std::vector<uint8_t> &v) {
                YourType t;
                std::memcpy(&t, v.data(), v.size());
                return t;
            }
        );
    }
};

}
```

## Integration with CI

Add to your CI pipeline:

```yaml
- name: Build RapidCheck tests
  run: |
    cd testcode/rapidcheck
    mkdir build && cd build
    cmake .. && make
    
- name: Run RapidCheck tests
  run: |
    cd testcode/rapidcheck/build
    ctest --output-on-failure
```

## Test Execution

### Running Tests

Most test files support command-line arguments for selective test execution:

```bash
# Run all tests
./rapidcheck_cipher_update_test

# List available tests
./rapidcheck_cipher_update_test --list

# Run specific test(s)
./rapidcheck_cipher_update_test xts_32_bytes
./rapidcheck_cipher_update_test null_ctx ctr_outlen_equals_inlen

# Get help
./rapidcheck_cipher_update_test --help
```

### Available Tests for Cipher Update

The `rapidcheck_cipher_update_test` has 24 individual tests:

| Test Name | Description |
|-----------|-------------|
| `null_ctx` | Tests NULL context handling |
| `null_in_nonzero_len` | Tests NULL input with non-zero length |
| `null_in_zero_len` | Tests NULL input with zero length |
| `null_out` | Tests NULL output buffer |
| `null_outlen` | Tests NULL output length pointer |
| `xts_small_input` | Tests XTS with input < BLOCKSIZE (16 bytes) - should fail |
| `xts_minimum_input` | Tests XTS with input >= BLOCKSIZE (16 bytes) - should succeed |
| `non_xts_small_input` | Tests non-XTS modes with small input |
| `all_valid_params` | Tests with all valid parameters |
| `ctr_outlen_equals_inlen` | Tests CTR mode output length equals input length |
| `block_cipher_outlen_invariant` | Tests block cipher output invariants |
| `xts_outlen_equals_inlen` | Tests XTS mode output length equals input length |
| `xts_final_no_output` | Tests XTS Final outputs 0 bytes |
| `outlen_non_negative` | Tests output length is non-negative |
| `cbc_small_input` | Tests CBC with input < block size |
| `cbc_exact_block` | Tests CBC with exact block size |
| `cbc_non_block_multiple` | Tests CBC with non-block-multiple input |
| `xts_16_bytes` | Tests XTS with exactly 16 bytes (minimum) |
| `xts_various_lengths` | Tests XTS with various input lengths (16-256 bytes) |
| `update_before_init` | Tests Update called before Init |
| `update_after_final` | Tests Update called after Final |
| `enc_dec` | Tests both encryption and decryption |
| `multiple_updates` | Tests multiple sequential Update calls |

### XTS Mode Behavior (Updated 2026-04-03)

After upstream commit `741f6b48`, XTS mode behavior has changed:

**Old Behavior (Before Commit)**:
- Update reserved last 2 blocks for Final processing
- `outLen = ((inLen / 16) - 2) * 16`
- Minimum input was 32 bytes (2 blocks)

**New Behavior (After Commit)**:
- Each Update call processes all input data
- `outLen == inLen` on success
- Minimum input is 16 bytes (1 block)
- Final outputs 0 bytes (no additional data)
- Partial blocks are processed in Update, not Final

This aligns XTS behavior with stream ciphers like CTR.

### Debugging Failed Tests

When a test fails, you can run it in isolation for easier debugging:

```bash
# 1. Run all tests to find failures
./rapidcheck_cipher_update_test

# 2. Run the specific failing test
./rapidcheck_cipher_update_test xts_32_bytes

# 3. Reproduce with the exact seed from the failure
RC_PARAMS="seed=9023039774416759098" ./rapidcheck_cipher_update_test xts_32_bytes
```

## Comparison with DeepState

| Feature | RapidCheck | DeepState |
|---------|------------|-----------|
| Test style | Property-based | Google Test-like |
| Execution | Random testing | Symbolic execution + fuzzing |
| Shrinking | Yes | Yes |
| Backends | Native only | angr, Manticore, AFL, libFuzzer |
| Best for | Quick property checks | Deep vulnerability finding |

Use **RapidCheck** for quick property verification during development.
Use **DeepState** for thorough symbolic/fuzzing analysis before release.