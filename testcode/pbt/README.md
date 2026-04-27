# openHiTLS Property-Based Tests

Property-based tests for the openHiTLS crypto library using [rapidcheck](https://github.com/emil-e/rapidcheck).

## Test Suite

| Module | Executable | Tests | Approach | Oracle |
|--------|-----------|-------|----------|--------|
| **DRBG** | `pbt_drbg` | 9 | A+B (rc::state::Command) | Self-model |
| **HMAC** | `pbt_hmac` | 10 | A (streaming, reinit, negative) | Self |
| **HMAC** | `pbt_hmac_refmodel` | 1 | B (full state-match) | OpenSSL HMAC |
| **CMAC** | `pbt_cmac` | 8 | A (K1/K2 boundary, streaming) | Self |
| **CMAC** | `pbt_cmac_refmodel` | 1 | B (full state-match) | OpenSSL CMAC |
| **GCM** | `pbt_gcm` | 7 | A (roundtrip, AEAD ordering) | Self |
| **Entropy** | `pbt_entropy` | 9 | A+B (isWork state machine) | Self |

## Prerequisites

```bash
# rapidcheck — C++ property-based testing
git clone https://github.com/emil-e/rapidcheck.git
cd rapidcheck && mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make -j$(nproc) && sudo make install

# OpenSSL (required by reference model tests)
# macOS: already installed
# Linux: sudo apt install libssl-dev
```

## Build

```bash
cd openHiTLS
mkdir build && cd build

# Build with PBT tests enabled
cmake .. \
  -DCMAKE_BUILD_TYPE=Debug \
  -DRAPIDCHECK_DIR=/usr/local \
  -DOpenssl_DIR=$(pkg-config --variable=libdir openssl 2>/dev/null || echo /usr/local/lib)

# Build all PBT executables
make pbt_drbg pbt_hmac pbt_hmac_refmodel pbt_cmac pbt_cmac_refmodel pbt_gcm pbt_entropy
```

## Run

```bash
# Run all PBT tests via CTest
cd build
ctest -R "^pbt_" --output-on-failure

# Run individual tests with rapidcheck config
./pbt_hmac_refmodel          # 100 iterations (default)

# CI profile: 2000 iterations, deterministic seed
RC_PARAMS="max_success=2000 seed=42" ./pbt_drbg

# Reproduce a failure with the reported seed
RC_PARAMS="max_success=2000 seed=9928307433081493900" ./pbt_hmac
```

## Test Design

### Approach A — Property-Based Oracle

Properties that must hold for all generated inputs:

| Property | Checks |
|----------|--------|
| **Streaming** | Any split of Update chunks produces the same Final output |
| **Round-trip** | Deinit + Init restores working state |
| **Reinit equivalence** | Reinit preserves key state, clears message state |
| **DupCtx independence** | Deep copy produces identical MAC independently |
| **Negative** | Invalid inputs (NULL, oversize, wrong key length) returned as errors |
| **Invariant** | Internal counters/state obey documented rules |

### Approach B — Reference Model Oracle

The reference model runs in parallel with the real implementation:

```
For every generated operation sequence:
  real_impl(op).return_code == ref_model(op).return_code
  real_impl(op).final_mac   == ref_model(op).final_mac    (OpenSSL)
```

Reference model tests use `rc::state::Command<Model, Sut>` objects that implement:
- `checkPreconditions(s)` — when is this command valid?
- `apply(s)` — apply to the model (tracks expected state)
- `run(s0, sut)` — run on the real impl + assert output matches model

## Directory Layout

```
testcode/pbt/
├── CMakeLists.txt
├── README.md
└── crypto/
    ├── drbg/
    │   └── test_pbt_drbg.cpp          # 5 stateful commands + invariants
    ├── hmac/
    │   ├── test_pbt_hmac.cpp           # 10 streaming + negative tests
    │   └── test_pbt_hmac_refmodel.cpp  # OpenSSL HMAC reference model oracle
    ├── cmac/
    │   ├── test_pbt_cmac.cpp           # 8 K1/K2 boundary + streaming
    │   └── test_pbt_cmac_refmodel.cpp  # OpenSSL CMAC reference model oracle
    ├── gcm/
    │   └── test_pbt_gcm.cpp            # 7 encrypt/decrypt roundtrip + AEAD
    └── entropy/
        └── test_pbt_entropy.cpp        # 9 isWork state machine + ctrl guards
```

## Debugging Failures

```bash
# rapidcheck prints a minimal counterexample on failure:
# ┌─────────────────────────────────────────
# │ Falsifiable after 12 tests and 10 shrinks
# │ Init(keyLen=16)
# │ Update(len=32)
# │ Final
# │   Expected: mac[0..15] = <OpenSSL MAC>
# │   Actual:   mac[0..15] = <wrong MAC>
# │ main.cpp:123: RC_ASSERT(memcmp(...) == 0)

# Pin the failing seed for reproducibility
RC_PARAMS="seed=<reported_seed>" ./pbt_hmac_refmodel

# Run with verbose output
RC_PARAMS="verbose_progress=1" ./pbt_drbg
```

## Extending

To add PBT tests for a new module:

1. Create `testcode/pbt/crypto/<module>/test_pbt_<module>.cpp`
2. Implement Approach A properties (streaming, negative, invariants)
3. If the module has a well-known spec (RFC, NIST), add a reference model test using OpenSSL as oracle
4. Register in `CMakeLists.txt` with `add_pbt_test(<module> ...)`
