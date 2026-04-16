include(FetchContent)

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(openHiTLS_RapidCheck)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(openHiTLS_SRC "${PROJECT_SOURCE_DIR}/../..")

option(RAPIDCHECK_BUILD_TESTS "Build RapidCheck tests" OFF)

# Find OpenSSL for reference model testing (differential testing)
find_package(OpenSSL REQUIRED)

FetchContent_Declare(
    rapidcheck
    GIT_REPOSITORY https://github.com/emil-e/rapidcheck.git
    GIT_TAG master  # or a specific tag like v1.0.0
)

FetchContent_MakeAvailable(rapidcheck)


set(TEST_INCLUDE_DIRS
    ${openHiTLS_SRC}/include
    ${openHiTLS_SRC}/include/crypto
    ${openHiTLS_SRC}/include/bsl
    ${openHiTLS_SRC}/apps/include
    ${openHiTLS_SRC}/crypto/aes/include
    ${openHiTLS_SRC}/crypto/sm3/include
    ${openHiTLS_SRC}/crypto/sm4/include
    ${openHiTLS_SRC}/crypto/hmac/include
    ${openHiTLS_SRC}/crypto/sha2/include
    ${openHiTLS_SRC}/crypto/sha1/include
    ${openHiTLS_SRC}/crypto/md5/include
    ${openHiTLS_SRC}/crypto/bn/include
    ${openHiTLS_SRC}/crypto/chacha20/include
    ${openHiTLS_SRC}/crypto/include
    ${openHiTLS_SRC}/crypto/eal/include
    ${openHiTLS_SRC}/crypto/provider/include
    ${openHiTLS_SRC}/crypto/hkdf/include
    ${openHiTLS_SRC}/crypto/kdf/include
    ${openHiTLS_SRC}/bsl/include
    ${openHiTLS_SRC}/bsl/sal/include
    ${openHiTLS_SRC}/bsl/err/include
    ${openHiTLS_SRC}/bsl/params/include
    ${openHiTLS_SRC}/bsl/core/include
    ${openHiTLS_SRC}/bsl/base64/include
    ${openHiTLS_SRC}/bsl/buffer/include
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/platform/Secure_C/include
)

# Full set of compile definitions extracted from the openHiTLS build system
set(HITLS_COMMON_DEFS
    HITLS_CRYPTO
    HITLS_CRYPTO_BN
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_DRBG
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_EALINIT
    HITLS_CRYPTO_ENTROPY
    HITLS_CRYPTO_GHASH
    HITLS_CRYPTO_HPKE
    HITLS_CRYPTO_KDF
    HITLS_CRYPTO_MAC
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_MODES
    HITLS_CRYPTO_PKEY
    HITLS_CRYPTO_PROVIDER
    HITLS_BSL
    HITLS_BSL_ERR
    HITLS_BSL_SAL
    HITLS_BSL_SAL_MEM
    HITLS_BSL_SAL_STR
    HITLS_BSL_SAL_THREAD
    HITLS_BSL_PARAMS
    HITLS_SIXTY_FOUR_BITS
    HITLS_CRYPTO_EAL_REPORT
    HITLS_CRYPTO_RAND_CB
    HITLS_CRYPTO_NO_AUXVAL
)

set(HITLS_COMMON_LIBS
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# EAL Cipher Update Tests (PUBLIC API - CRYPT_EAL_CipherUpdate)
# Generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001
# =============================================================================
add_executable(rapidcheck_cipher_update_test rapidcheck_cipher_update_test.cpp)
target_include_directories(rapidcheck_cipher_update_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_cipher_update_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_SM4
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_XTS
)
target_link_libraries(rapidcheck_cipher_update_test ${HITLS_COMMON_LIBS})

# =============================================================================
# AES OpenSSL Reference Model Tests (Differential Testing)
# Generalizes SDV_CRYPTO_AES_ENCRYPT_FUNC_TC001 using OpenSSL as oracle
# =============================================================================
add_executable(rapidcheck_aes_openssl_ref_test rapidcheck_aes_openssl_ref_test.cpp)
target_include_directories(rapidcheck_aes_openssl_ref_test PRIVATE
    ${TEST_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)
target_compile_definitions(rapidcheck_aes_openssl_ref_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_GCM
    HITLS_CRYPTO_XTS
)
target_link_libraries(rapidcheck_aes_openssl_ref_test
    rapidcheck
    OpenSSL::SSL
    OpenSSL::Crypto
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# MD (Hash/Digest) Tests
# Generalizes unit tests from sha2, md5, sha3 test suites
# Covers: MD5, SHA1, SHA224/256/384/512, SHA3-224/256/384/512, SM3
# =============================================================================
add_executable(rapidcheck_md_test rapidcheck_md_test.cpp)
target_include_directories(rapidcheck_md_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_md_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_SHA3
    HITLS_CRYPTO_SM3
)
target_link_libraries(rapidcheck_md_test ${HITLS_COMMON_LIBS})

# =============================================================================
# MAC (HMAC / CMAC) Tests
# Generalizes unit tests from hmac test suite
# Covers: HMAC-MD5/SHA1/SHA2/SHA3/SM3, CMAC-AES128/192/256, CMAC-SM4
# =============================================================================
add_executable(rapidcheck_mac_test rapidcheck_mac_test.cpp)
target_include_directories(rapidcheck_mac_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_mac_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_HMAC
    HITLS_CRYPTO_CMAC
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_SHA3
    HITLS_CRYPTO_SM3
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_SM4
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
)
target_link_libraries(rapidcheck_mac_test ${HITLS_COMMON_LIBS})

# =============================================================================
# KDF (HKDF) Tests
# Generalizes unit tests from hkdf test suite
# Covers: HKDF-SHA1/SHA224/SHA256/SHA384/SHA512/SM3 (FULL, EXTRACT, EXPAND modes)
# =============================================================================
add_executable(rapidcheck_kdf_test rapidcheck_kdf_test.cpp)
target_include_directories(rapidcheck_kdf_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_kdf_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_HKDF
    HITLS_CRYPTO_HMAC
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_SM3
)
target_link_libraries(rapidcheck_kdf_test ${HITLS_COMMON_LIBS})

# =============================================================================
# PBKDF2 Tests
# Generalizes unit tests from pbkdf2 test suite
# Covers: determinism, sensitivity, output length, null inputs, all MAC algs
# =============================================================================
add_executable(rapidcheck_pbkdf2_test rapidcheck_pbkdf2_test.cpp)
target_include_directories(rapidcheck_pbkdf2_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_pbkdf2_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_PBKDF2
    HITLS_CRYPTO_HMAC
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_SM3
)
target_link_libraries(rapidcheck_pbkdf2_test ${HITLS_COMMON_LIBS})

# =============================================================================
# ChaCha20-Poly1305 Tests
# Generalizes unit tests from chacha-poly test suite
# Covers: null inputs, invalid params, roundtrip, determinism, sensitivity,
# tag integrity, stream outLen == inLen
# =============================================================================
add_executable(rapidcheck_chacha20poly1305_test rapidcheck_chacha20poly1305_test.cpp)
target_include_directories(rapidcheck_chacha20poly1305_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_chacha20poly1305_test PRIVATE
    ${HITLS_COMMON_DEFS}
    HITLS_CRYPTO_CHACHA20
    HITLS_CRYPTO_POLY1305
    HITLS_CRYPTO_CHACHA20_POLY1305
)
target_link_libraries(rapidcheck_chacha20poly1305_test ${HITLS_COMMON_LIBS})

# =============================================================================
# Base64 Tests
# Covers: encode/decode roundtrip, streaming roundtrip, output length,
# valid alphabet, empty input, null inputs, invalid input handling
# =============================================================================
add_executable(rapidcheck_base64_test rapidcheck_base64_test.cpp)
target_include_directories(rapidcheck_base64_test PRIVATE
    ${TEST_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/bsl/base64/include
)
target_compile_definitions(rapidcheck_base64_test PRIVATE ${HITLS_COMMON_DEFS})
target_link_libraries(rapidcheck_base64_test ${HITLS_COMMON_LIBS})

# =============================================================================
# Test Registration
# =============================================================================
enable_testing()
add_test(NAME RapidCheck_Cipher_Update COMMAND rapidcheck_cipher_update_test)
add_test(NAME RapidCheck_AES_OpenSSL_Ref COMMAND rapidcheck_aes_openssl_ref_test)
add_test(NAME RapidCheck_MD COMMAND rapidcheck_md_test)
add_test(NAME RapidCheck_MAC COMMAND rapidcheck_mac_test)
add_test(NAME RapidCheck_KDF COMMAND rapidcheck_kdf_test)
add_test(NAME RapidCheck_PBKDF2 COMMAND rapidcheck_pbkdf2_test)
add_test(NAME RapidCheck_ChaCha20Poly1305 COMMAND rapidcheck_chacha20poly1305_test)
add_test(NAME RapidCheck_Base64 COMMAND rapidcheck_base64_test)