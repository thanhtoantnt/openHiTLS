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
#   make pbt_drbg pbt_hmac pbt_cmac

cmake_minimum_required(VERSION 3.14)

# Find rapidcheck
find_package(rapidcheck REQUIRED)

# Helper: add a PBT test executable
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

# DRBG: State machine + invariants
add_pbt_test(drbg
    testcode/pbt/crypto/drbg/test_pbt_drbg.cpp
)

# HMAC: Streaming + reinit equivalence + negative
add_pbt_test(hmac
    testcode/pbt/crypto/hmac/test_pbt_hmac.cpp
)

# CMAC: Partial block accumulation + K1/K2 sub-key
add_pbt_test(cmac
    testcode/pbt/crypto/cmac/test_pbt_cmac.cpp
    # TODO: write CMAC tests with partial block boundary properties
)
