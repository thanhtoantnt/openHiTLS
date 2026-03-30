cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(openHiTLS_RapidCheck)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(openHiTLS_SRC "${PROJECT_SOURCE_DIR}/../..")

option(RAPIDCHECK_BUILD_TESTS "Build RapidCheck tests" OFF)

add_subdirectory(
    /Users/thanhtoantnt/workspace/opencode-demo/rapidcheck
    ${CMAKE_BINARY_DIR}/rapidcheck-build
)

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
    ${openHiTLS_SRC}/crypto/md5/include
    ${openHiTLS_SRC}/crypto/bn/include
    ${openHiTLS_SRC}/crypto/include
    ${openHiTLS_SRC}/crypto/eal/include
    ${openHiTLS_SRC}/crypto/provider/include
    ${openHiTLS_SRC}/bsl/include
    ${openHiTLS_SRC}/bsl/sal/include
    ${openHiTLS_SRC}/bsl/err/include
    ${openHiTLS_SRC}/bsl/params/include
    ${openHiTLS_SRC}/bsl/core/include
    ${openHiTLS_SRC}/config/macro_config
    ${openHiTLS_SRC}/platform/Secure_C/include
)

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

enable_testing()
add_test(NAME RapidCheck_AES COMMAND rapidcheck_aes_test)
add_test(NAME RapidCheck_Hash COMMAND rapidcheck_hash_test)
add_test(NAME RapidCheck_Opt COMMAND rapidcheck_opt_test)
# add_test(NAME RapidCheck_HMAC COMMAND rapidcheck_hmac_test)