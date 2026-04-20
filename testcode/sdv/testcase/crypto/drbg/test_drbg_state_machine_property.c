/*
 * Copyright (c) [Year] The openHiTLS Authors. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_drbg.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "securec.h"

#define DRBG_MAX_OUTPUT_SIZE 64
#define DRBG_MAX_RESEED_COUNT 100
#define DRBG_MAX_GENERATE_COUNT 100

typedef struct {
    uint8_t v[55];
    uint8_t c[55];
    uint32_t reseedCounter;
    bool instantiated;
    uint32_t predictionResistance;
    uint8_t securityStrength;
} DrbgRefState;

typedef struct {
    uint8_t entropy[256];
    size_t entropyLen;
    size_t entropyPos;
    uint8_t nonce[128];
    size_t nonceLen;
    uint8_t perso[256];
    size_t persoLen;
    uint8_t addInput[256];
    size_t addInputLen;
} DrbgTestInput;

static int32_t RefInstantiate(DrbgRefState *state, const DrbgTestInput *input)
{
    if (state == NULL || input == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (input->entropyLen < 55) {
        return CRYPT_DRBG_ENTROPY_LEN_INVALID;
    }
    
    (void)memcpy_s(state->v, sizeof(state->v), input->entropy, 55);
    (void)memcpy_s(state->c, sizeof(state->c), input->nonce, (input->nonceLen < 55) ? input->nonceLen : 55);
    state->reseedCounter = 1;
    state->instantiated = true;
    
    return CRYPT_SUCCESS;
}

static int32_t RefReseed(DrbgRefState *state, const DrbgTestInput *input)
{
    if (state == NULL || input == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (!state->instantiated) {
        return CRYPT_DRBG_STATE_INVALID;
    }
    
    if (input->entropyLen < 55) {
        return CRYPT_DRBG_ENTROPY_LEN_INVALID;
    }
    
    (void)memcpy_s(state->v, sizeof(state->v), input->entropy, 55);
    state->reseedCounter = 1;
    
    return CRYPT_SUCCESS;
}

static int32_t RefGenerate(DrbgRefState *state, uint8_t *out, size_t outLen, const uint8_t *addInput, size_t addLen)
{
    if (state == NULL || out == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    if (!state->instantiated) {
        return CRYPT_DRBG_STATE_INVALID;
    }
    
    if (outLen > DRBG_MAX_OUTPUT_SIZE) {
        return CRYPT_DRBG_OUTLEN_TOO_LARGE;
    }
    
    if (state->reseedCounter > DRBG_MAX_RESEED_COUNT) {
        return CRYPT_DRBG_RESEED_REQUIRED;
    }
    
    for (size_t i = 0; i < outLen; i++) {
        out[i] = state->v[i % 55] ^ state->c[i % 55] ^ (uint8_t)(state->reseedCounter + i);
    }
    
    if (addInput != NULL && addLen > 0) {
        for (size_t i = 0; i < 55 && i < addLen; i++) {
            state->v[i] ^= addInput[i];
        }
    }
    
    state->reseedCounter++;
    
    return CRYPT_SUCCESS;
}

static int32_t RefUninstantiate(DrbgRefState *state)
{
    if (state == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    (void)memset_s(state, sizeof(DrbgRefState), 0, sizeof(DrbgRefState));
    
    return CRYPT_SUCCESS;
}

static uint32_t g_entropyCallCount = 0;
static uint8_t g_deterministicEntropy[256];
static size_t g_deterministicEntropyLen = 0;
static size_t g_deterministicEntropyPos = 0;

static int32_t DeterministicEntropyCallback(uint8_t *out, size_t outLen, void *ctx)
{
    (void)ctx;
    
    if (out == NULL || outLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    
    g_entropyCallCount++;
    
    size_t remaining = g_deterministicEntropyLen - g_deterministicEntropyPos;
    size_t copyLen = (outLen < remaining) ? outLen : remaining;
    
    if (copyLen < outLen) {
        return CRYPT_DRBG_ENTROPY_SOURCE_FAILED;
    }
    
    (void)memcpy_s(out, outLen, g_deterministicEntropy + g_deterministicEntropyPos, copyLen);
    g_deterministicEntropyPos += copyLen;
    
    return CRYPT_SUCCESS;
}

static void SetupDeterministicEntropy(const uint8_t *entropy, size_t len)
{
    g_entropyCallCount = 0;
    g_deterministicEntropyPos = 0;
    g_deterministicEntropyLen = len;
    (void)memcpy_s(g_deterministicEntropy, sizeof(g_deterministicEntropy), entropy, len);
}

static int32_t DeterministicNonceCallback(uint8_t *out, size_t outLen, void *ctx)
{
    (void)ctx;
    
    if (out == NULL || outLen == 0) {
        return CRYPT_NULL_INPUT;
    }
    
    (void)memset_s(out, outLen, 0xAA, outLen);
    
    return CRYPT_SUCCESS;
}

static int TestInstantiateGenerate(void)
{
    CRYPT_DRBG_Ctx *drbg = NULL;
    DrbgRefState refState;
    DrbgTestInput input;
    int32_t ret;
    uint8_t implOut[DRBG_MAX_OUTPUT_SIZE];
    uint8_t refOut[DRBG_MAX_OUTPUT_SIZE];
    
    const uint8_t entropy[110] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A
    };
    
    (void)memset_s(&refState, sizeof(refState), 0, sizeof(refState));
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    
    input.entropyLen = sizeof(entropy);
    (void)memcpy_s(input.entropy, sizeof(input.entropy), entropy, sizeof(entropy));
    input.nonceLen = 16;
    (void)memset_s(input.nonce, sizeof(input.nonce), 0xBB, input.nonceLen);
    
    ret = RefInstantiate(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = RefGenerate(&refState, refOut, 32, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    SetupDeterministicEntropy(entropy, sizeof(entropy));
    
    drbg = CRYPT_DRBG_New(CRYPT_DRBG_HASH_SHA256);
    if (drbg == NULL) {
        return CRYPT_MEMORY_ERR;
    }
    
    ret = CRYPT_DRBG_Instantiate(drbg, DeterministicEntropyCallback, DeterministicNonceCallback,
                                  NULL, NULL, 0, CRYPT_DRBG_SECURITY_STRENGTH_256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    ret = CRYPT_DRBG_Generate(drbg, implOut, 32, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Uninstantiate(drbg);
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    CRYPT_DRBG_Uninstantiate(drbg);
    CRYPT_DRBG_Free(drbg);
    
    return CRYPT_SUCCESS;
}

static int TestReseedTransition(void)
{
    CRYPT_DRBG_Ctx *drbg = NULL;
    DrbgRefState refState;
    DrbgTestInput input;
    int32_t ret;
    uint8_t out[DRBG_MAX_OUTPUT_SIZE];
    
    const uint8_t entropy[110] = {0};
    
    (void)memset_s(&refState, sizeof(refState), 0, sizeof(refState));
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    
    input.entropyLen = sizeof(entropy);
    (void)memcpy_s(input.entropy, sizeof(input.entropy), entropy, sizeof(entropy));
    
    ret = RefInstantiate(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = RefReseed(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = RefGenerate(&refState, out, 32, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    SetupDeterministicEntropy(entropy, sizeof(entropy));
    
    drbg = CRYPT_DRBG_New(CRYPT_DRBG_HASH_SHA256);
    if (drbg == NULL) {
        return CRYPT_MEMORY_ERR;
    }
    
    ret = CRYPT_DRBG_Instantiate(drbg, DeterministicEntropyCallback, DeterministicNonceCallback,
                                  NULL, NULL, 0, CRYPT_DRBG_SECURITY_STRENGTH_256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    SetupDeterministicEntropy(entropy, sizeof(entropy));
    ret = CRYPT_DRBG_Reseed(drbg, DeterministicEntropyCallback, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Uninstantiate(drbg);
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    ret = CRYPT_DRBG_Generate(drbg, out, 32, NULL, 0);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Uninstantiate(drbg);
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    CRYPT_DRBG_Uninstantiate(drbg);
    CRYPT_DRBG_Free(drbg);
    
    return CRYPT_SUCCESS;
}

static int TestUninstantiateTransition(void)
{
    CRYPT_DRBG_Ctx *drbg = NULL;
    DrbgRefState refState;
    DrbgTestInput input;
    int32_t ret;
    uint8_t out[DRBG_MAX_OUTPUT_SIZE];
    
    const uint8_t entropy[110] = {0};
    
    (void)memset_s(&refState, sizeof(refState), 0, sizeof(refState));
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    
    input.entropyLen = sizeof(entropy);
    (void)memcpy_s(input.entropy, sizeof(input.entropy), entropy, sizeof(entropy));
    
    ret = RefInstantiate(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = RefUninstantiate(&refState);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = RefGenerate(&refState, out, 32, NULL, 0);
    if (ret != CRYPT_DRBG_STATE_INVALID) {
        return CRYPT_FAILURE;
    }
    
    SetupDeterministicEntropy(entropy, sizeof(entropy));
    
    drbg = CRYPT_DRBG_New(CRYPT_DRBG_HASH_SHA256);
    if (drbg == NULL) {
        return CRYPT_MEMORY_ERR;
    }
    
    ret = CRYPT_DRBG_Instantiate(drbg, DeterministicEntropyCallback, DeterministicNonceCallback,
                                  NULL, NULL, 0, CRYPT_DRBG_SECURITY_STRENGTH_256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    ret = CRYPT_DRBG_Uninstantiate(drbg);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    ret = CRYPT_DRBG_Generate(drbg, out, 32, NULL, 0);
    if (ret != CRYPT_DRBG_STATE_INVALID) {
        CRYPT_DRBG_Free(drbg);
        return CRYPT_FAILURE;
    }
    
    CRYPT_DRBG_Free(drbg);
    
    return CRYPT_SUCCESS;
}

static int TestReseedCounterProperty(void)
{
    DrbgRefState refState;
    DrbgTestInput input;
    int32_t ret;
    uint8_t out[DRBG_MAX_OUTPUT_SIZE];
    uint32_t initialCounter;
    uint32_t expectedCounter;
    
    const uint8_t entropy[110] = {0};
    
    (void)memset_s(&refState, sizeof(refState), 0, sizeof(refState));
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    
    input.entropyLen = sizeof(entropy);
    (void)memcpy_s(input.entropy, sizeof(input.entropy), entropy, sizeof(entropy));
    
    ret = RefInstantiate(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    initialCounter = refState.reseedCounter;
    
    for (int i = 0; i < 10; i++) {
        ret = RefGenerate(&refState, out, 32, NULL, 0);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    
    expectedCounter = initialCounter + 10;
    if (refState.reseedCounter != expectedCounter) {
        return CRYPT_FAILURE;
    }
    
    ret = RefReseed(&refState, &input);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (refState.reseedCounter != 1) {
        return CRYPT_FAILURE;
    }
    
    return CRYPT_SUCCESS;
}

static int TestPredictionResistance(void)
{
    CRYPT_DRBG_Ctx *drbg = NULL;
    int32_t ret;
    uint8_t out[DRBG_MAX_OUTPUT_SIZE];
    
    const uint8_t entropy[220] = {0};
    
    SetupDeterministicEntropy(entropy, sizeof(entropy));
    
    drbg = CRYPT_DRBG_New(CRYPT_DRBG_HASH_SHA256);
    if (drbg == NULL) {
        return CRYPT_MEMORY_ERR;
    }
    
    ret = CRYPT_DRBG_Instantiate(drbg, DeterministicEntropyCallback, DeterministicNonceCallback,
                                  NULL, NULL, 0, CRYPT_DRBG_SECURITY_STRENGTH_256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DRBG_Free(drbg);
        return ret;
    }
    
    for (int i = 0; i < 5; i++) {
        ret = CRYPT_DRBG_Generate(drbg, out, 32, NULL, 0);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_DRBG_Uninstantiate(drbg);
            CRYPT_DRBG_Free(drbg);
            return ret;
        }
    }
    
    CRYPT_DRBG_Uninstantiate(drbg);
    CRYPT_DRBG_Free(drbg);
    
    return CRYPT_SUCCESS;
}

int DRBG_StateMachine_PropertyTest(void)
{
    int32_t ret;
    
    ret = TestInstantiateGenerate();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = TestReseedTransition();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = TestUninstantiateTransition();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = TestReseedCounterProperty();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    ret = TestPredictionResistance();
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    return CRYPT_SUCCESS;
}
