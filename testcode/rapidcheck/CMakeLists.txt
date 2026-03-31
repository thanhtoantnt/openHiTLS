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

# =============================================================================
# AES Tests
# =============================================================================
add_executable(rapidcheck_aes_test rapidcheck_aes_test.cpp)
target_include_directories(rapidcheck_aes_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_aes_test PRIVATE
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_GCM
)
target_link_libraries(rapidcheck_aes_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# SM3/Hash Tests
# =============================================================================
add_executable(rapidcheck_hash_test rapidcheck_hash_test.cpp)
target_include_directories(rapidcheck_hash_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_hash_test PRIVATE
    HITLS_CRYPTO_SM3
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_hash_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# SHA2 Tests
# =============================================================================
add_executable(rapidcheck_sha2_test rapidcheck_sha2_test.cpp)
target_include_directories(rapidcheck_sha2_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_sha2_test PRIVATE
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_sha2_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# SM4 Tests
# =============================================================================
add_executable(rapidcheck_sm4_test rapidcheck_sm4_test.cpp)
target_include_directories(rapidcheck_sm4_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_sm4_test PRIVATE
    HITLS_CRYPTO_SM4
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
)
target_link_libraries(rapidcheck_sm4_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# BN (Big Number) Tests
# =============================================================================
add_executable(rapidcheck_bn_test rapidcheck_bn_test.cpp)
target_include_directories(rapidcheck_bn_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_bn_test PRIVATE
    HITLS_CRYPTO_BN
    HITLS_CRYPTO_EAL_BN
    HITLS_SIXTY_FOUR_BITS
)
target_link_libraries(rapidcheck_bn_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# Base64 Tests
# =============================================================================
add_executable(rapidcheck_base64_test rapidcheck_base64_test.cpp)
target_include_directories(rapidcheck_base64_test PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(rapidcheck_base64_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# App Opt Tests
# =============================================================================
add_executable(rapidcheck_opt_test rapidcheck_opt_test.cpp)
target_include_directories(rapidcheck_opt_test PRIVATE ${TEST_INCLUDE_DIRS})
target_sources(rapidcheck_opt_test PRIVATE
    ${openHiTLS_SRC}/apps/src/app_opt.c
    ${openHiTLS_SRC}/apps/src/app_print.c
)
target_compile_definitions(rapidcheck_opt_test PRIVATE
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_SM3
)
target_link_libraries(rapidcheck_opt_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# MD5 Tests
# =============================================================================
add_executable(rapidcheck_md5_test rapidcheck_md5_test.cpp)
target_include_directories(rapidcheck_md5_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_md5_test PRIVATE
    HITLS_CRYPTO_MD5
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_md5_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# SHA-1 Tests
# =============================================================================
add_executable(rapidcheck_sha1_test rapidcheck_sha1_test.cpp)
target_include_directories(rapidcheck_sha1_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_sha1_test PRIVATE
    HITLS_CRYPTO_SHA1
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_sha1_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# ChaCha20 Tests
# =============================================================================
add_executable(rapidcheck_chacha20_test rapidcheck_chacha20_test.cpp)
target_include_directories(rapidcheck_chacha20_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_chacha20_test PRIVATE
    HITLS_CRYPTO_CHACHA20
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_chacha20_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# Buffer Tests
# =============================================================================
add_executable(rapidcheck_buffer_test rapidcheck_buffer_test.cpp)
target_include_directories(rapidcheck_buffer_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_buffer_test PRIVATE
    HITLS_BSL_BUFFER
)
target_link_libraries(rapidcheck_buffer_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# Random Number Tests
# =============================================================================
add_executable(rapidcheck_rand_test rapidcheck_rand_test.cpp)
target_include_directories(rapidcheck_rand_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_rand_test PRIVATE
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_DRBG
    HITLS_CRYPTO_RAND
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_rand_test 
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# Edge Case Tests
# =============================================================================
add_executable(rapidcheck_edge_test rapidcheck_edge_test.cpp)
target_include_directories(rapidcheck_edge_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_edge_test PRIVATE
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_MD
    HITLS_CRYPTO_SHA2
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_edge_test
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

# =============================================================================
# EAL AES Init Tests (PUBLIC API - CRYPT_EAL_CipherInit)
# Generalizes SDV_CRYPTO_AES_INIT_API_TC001
# =============================================================================
add_executable(rapidcheck_eal_aes_init_test rapidcheck_eal_aes_init_test.cpp)
target_include_directories(rapidcheck_eal_aes_init_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_eal_aes_init_test PRIVATE
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_eal_aes_init_test
    rapidcheck
    ${openHiTLS_SRC}/build/libhitls_crypto.a
    ${openHiTLS_SRC}/build/libhitls_bsl.a
    ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
)

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
    HITLS_CRYPTO_AES
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_GCM
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_PROVIDER
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
# HMAC Tests (disabled - C++ keyword conflict)
# =============================================================================
# Note: rapidcheck_hmac_test is disabled because openHiTLS uses 'export' as a struct member name
# which conflicts with the C++ reserved keyword 'export'
# add_executable(rapidcheck_hmac_test rapidcheck_hmac_test.cpp)
# target_include_directories(rapidcheck_hmac_test PRIVATE ${TEST_INCLUDE_DIRS})
# target_compile_definitions(rapidcheck_hmac_test PRIVATE
#     HITLS_CRYPTO_HMAC
#     HITLS_CRYPTO_SM3
#     HITLS_CRYPTO_PROVIDER
# )
# target_link_libraries(rapidcheck_hmac_test 
#     rapidcheck
#     ${openHiTLS_SRC}/build/libhitls_crypto.a
#     ${openHiTLS_SRC}/build/libhitls_bsl.a
#     ${openHiTLS_SRC}/platform/Secure_C/lib/libboundscheck.a
# )

# =============================================================================
# Test Registration
# =============================================================================
enable_testing()
add_test(NAME RapidCheck_AES COMMAND rapidcheck_aes_test)
add_test(NAME RapidCheck_Hash COMMAND rapidcheck_hash_test)
add_test(NAME RapidCheck_SHA2 COMMAND rapidcheck_sha2_test)
add_test(NAME RapidCheck_SM4 COMMAND rapidcheck_sm4_test)
add_test(NAME RapidCheck_BN COMMAND rapidcheck_bn_test)
add_test(NAME RapidCheck_Base64 COMMAND rapidcheck_base64_test)
add_test(NAME RapidCheck_Opt COMMAND rapidcheck_opt_test)
add_test(NAME RapidCheck_MD5 COMMAND rapidcheck_md5_test)
add_test(NAME RapidCheck_SHA1 COMMAND rapidcheck_sha1_test)
add_test(NAME RapidCheck_ChaCha20 COMMAND rapidcheck_chacha20_test)
add_test(NAME RapidCheck_Buffer COMMAND rapidcheck_buffer_test)
add_test(NAME RapidCheck_Rand COMMAND rapidcheck_rand_test)
add_test(NAME RapidCheck_Edge COMMAND rapidcheck_edge_test)
# add_test(NAME RapidCheck_HMAC COMMAND rapidcheck_hmac_test)
add_test(NAME RapidCheck_AES_INIT COMMAND rapidcheck_eal_aes_init_test)
add_test(NAME RapidCheck_AES_OpenSSL_Ref COMMAND rapidcheck_aes_openssl_ref_test)
