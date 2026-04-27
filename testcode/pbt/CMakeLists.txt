# Property-Based Tests for openHiTLS
# Build system for rapidcheck-based PBT tests
#
# Requires:
#   - rapidcheck (https://github.com/emil-e/rapidcheck)
#   - openHiTLS crypto library built
#
# Build:
#   cd openHiTLS && mkdir build && cd build
#   cmake .. -DRAPIDCHECK_DIR=/path/to/rapidcheck
#   make pbt_drbg pbt_hmac pbt_cmac pbt_gcm

cmake_minimum_required(VERSION 3.14)

find_package(rapidcheck REQUIRED)

function(add_pbt_test name sources)
    add_executable(pbt_${name} ${sources} ${ARGN})
    target_include_directories(pbt_${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/crypto
    )
    target_link_libraries(pbt_${name} PRIVATE
        openhitls
        rapidcheck
    )
    set_target_properties(pbt_${name} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )
    enable_testing()
    add_test(NAME pbt_${name} COMMAND pbt_${name})
endfunction()

# DRBG: State machine (5 commands: Instantiate/Generate/Reseed/Uninstantiate/Free)
#       + invariants + negative + round-trip (9 tests)
add_pbt_test(drbg
    testcode/pbt/crypto/drbg/test_pbt_drbg.cpp
)

# HMAC: Streaming + reinit equivalence + negative + dup independence + round-trip (10 tests)
add_pbt_test(hmac
    testcode/pbt/crypto/hmac/test_pbt_hmac.cpp
)

# HMAC Reference Model: Approach B — impl matches OpenSSL for all operation sequences
add_pbt_test(hmac_refmodel
    testcode/pbt/crypto/hmac/test_pbt_hmac_refmodel.cpp
)

# CMAC: Streaming + block boundary (K1/K2 sub-keys) + reinit (8 tests)
add_pbt_test(cmac
    testcode/pbt/crypto/cmac/test_pbt_cmac.cpp
)

# CMAC Reference Model: Approach B — impl matches OpenSSL for all operation sequences
add_pbt_test(cmac_refmodel
    testcode/pbt/crypto/cmac/test_pbt_cmac_refmodel.cpp
)

# GCM: Encrypt/decrypt roundtrip + streaming + AAD ordering + wrong tag + tag length + IV edges (7 tests)
add_pbt_test(gcm
    testcode/pbt/crypto/gcm/test_pbt_gcm.cpp
)

# Entropy: Init/Deinit state machine + pre-init rejection + double init + ctrl guards + Free safety (9 tests)
add_pbt_test(entropy
    testcode/pbt/crypto/entropy/test_pbt_entropy.cpp
)
