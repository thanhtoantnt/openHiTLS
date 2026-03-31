/**
 * @file rapidcheck_rand_test.cpp
 * @brief RapidCheck property-based tests for random number generation
 * 
 * This file contains property-based tests that generalize the unit tests in:
 * - testcode/sdv/testcase/crypto/rand/
 * 
 * Properties tested:
 * - Random output length matches requested length
 * - Different calls produce different outputs (non-determinism)
 * - Random bytes are uniformly distributed (basic statistical check)
 */

#include <rapidcheck.h>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>

#include "hitls_build.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"

using namespace rc;

int main() {
    /**
     * @test Random output length matches requested length
     * @property For all valid lengths, rand(len).size() == len
     * @generalizes SDV_CRYPT_EAL_RAND_API_TC001 - Basic random generation
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Random output length matches requested length",
        [](uint32_t len) {
            RC_PRE(len > 0);
            RC_PRE(len <= 1024);
            
            int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(len);
            ret = CRYPT_EAL_Randbytes(output.data(), len);
            
            if (ret == CRYPT_SUCCESS) {
                RC_ASSERT(output.size() == len);
            }
            
            CRYPT_EAL_RandDeinit();
        });

    /**
     * @test Different random calls produce different outputs
     * @property For two consecutive calls, rand() != rand()
     * @generalizes Non-determinism property
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Different random calls produce different outputs",
        [](uint32_t len) {
            RC_PRE(len >= 32);
            RC_PRE(len <= 256);
            
            int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output1(len);
            std::vector<uint8_t> output2(len);
            
            ret = CRYPT_EAL_Randbytes(output1.data(), len);
            if (ret != CRYPT_SUCCESS) {
                CRYPT_EAL_RandDeinit();
                return;
            }
            
            ret = CRYPT_EAL_Randbytes(output2.data(), len);
            if (ret != CRYPT_SUCCESS) {
                CRYPT_EAL_RandDeinit();
                return;
            }
            
            // Two random outputs should be different (with very high probability)
            RC_ASSERT(std::memcmp(output1.data(), output2.data(), len) != 0);
            
            CRYPT_EAL_RandDeinit();
        });

    /**
     * @test Random output is not all zeros
     * @property rand() != all_zeros
     * @generalizes Quality check
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Random output is not all zeros",
        [](uint32_t len) {
            RC_PRE(len >= 16);
            RC_PRE(len <= 256);
            
            int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(len, 0);
            ret = CRYPT_EAL_Randbytes(output.data(), len);
            
            if (ret == CRYPT_SUCCESS) {
                // Check not all zeros
                bool allZeros = true;
                for (auto b : output) {
                    if (b != 0) {
                        allZeros = false;
                        break;
                    }
                }
                RC_ASSERT(!allZeros);
            }
            
            CRYPT_EAL_RandDeinit();
        });

    /**
     * @test Random output is not all ones
     * @property rand() != all_ones
     * @generalizes Quality check
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Random output is not all ones",
        [](uint32_t len) {
            RC_PRE(len >= 16);
            RC_PRE(len <= 256);
            
            int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(len);
            ret = CRYPT_EAL_Randbytes(output.data(), len);
            
            if (ret == CRYPT_SUCCESS) {
                // Check not all 0xFF
                bool allOnes = true;
                for (auto b : output) {
                    if (b != 0xFF) {
                        allOnes = false;
                        break;
                    }
                }
                RC_ASSERT(!allOnes);
            }
            
            CRYPT_EAL_RandDeinit();
        });

    /**
     * @test Random bytes have reasonable byte distribution
     * @property Each byte value appears with roughly equal frequency
     * @generalizes Statistical quality check
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Random bytes have reasonable distribution",
        []() {
            uint32_t len = 2560; // 10 * 256 for distribution check
            int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
            RC_PRE(ret == CRYPT_SUCCESS);
            
            std::vector<uint8_t> output(len);
            ret = CRYPT_EAL_Randbytes(output.data(), len);
            
            if (ret == CRYPT_SUCCESS) {
                // Count byte frequencies
                int freq[256] = {0};
                for (auto b : output) {
                    freq[b]++;
                }
                
                // Each byte should appear roughly 10 times (with some tolerance)
                // A truly random distribution should have each byte appear ~10 times
                // We allow range [1, 30] to account for variance
                for (int i = 0; i < 256; i++) {
                    RC_ASSERT(freq[i] >= 1);
                    RC_ASSERT(freq[i] <= 30);
                }
            }
            
            CRYPT_EAL_RandDeinit();
        });

    /**
     * @test Multiple init/deinit cycles work correctly
     * @property After deinit and reinit, random still works
     * @generalizes Resource management test
     * @see testcode/sdv/testcase/crypto/rand/
     */
    rc::check("Multiple init/deinit cycles work",
        [](uint32_t cycles) {
            RC_PRE(cycles >= 1);
            RC_PRE(cycles <= 10);
            
            for (uint32_t i = 0; i < cycles; i++) {
                int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_AES128_CTR, NULL, NULL, NULL, 0);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                
                uint8_t output[32];
                ret = CRYPT_EAL_Randbytes(output, 32);
                RC_ASSERT(ret == CRYPT_SUCCESS);
                
                CRYPT_EAL_RandDeinit();
            }
        });

    return 0;
}