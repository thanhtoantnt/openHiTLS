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
# EAL Cipher Update Tests (PUBLIC API - CRYPT_EAL_CipherUpdate)
# Generalizes SDV_CRYPTO_SM4_UPDATE_API_TC001
# =============================================================================
add_executable(rapidcheck_cipher_update_test rapidcheck_cipher_update_test.cpp)
target_include_directories(rapidcheck_cipher_update_test PRIVATE ${TEST_INCLUDE_DIRS})
target_compile_definitions(rapidcheck_cipher_update_test PRIVATE
    HITLS_CRYPTO_SM4
    HITLS_CRYPTO_ECB
    HITLS_CRYPTO_CBC
    HITLS_CRYPTO_CTR
    HITLS_CRYPTO_XTS
    HITLS_CRYPTO_EAL
    HITLS_CRYPTO_CIPHER
    HITLS_CRYPTO_PROVIDER
)
target_link_libraries(rapidcheck_cipher_update_test
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
# Test Registration
# =============================================================================
enable_testing()
add_test(NAME RapidCheck_Cipher_Update COMMAND rapidcheck_cipher_update_test)
add_test(NAME RapidCheck_AES_OpenSSL_Ref COMMAND rapidcheck_aes_openssl_ref_test)