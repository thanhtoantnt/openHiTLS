# Fix Proposal for XTS Block Alignment Bug (SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC002)

## Root Cause Analysis

### Current Implementation Problem

The bug is in `crypto/modes/src/modes.c:542`:

```c
int32_t MODES_CipherStreamProcess(void *processFuncs, void *ctx, const uint8_t *in, 
                                   uint32_t inLen, uint8_t *out, uint32_t *outLen) {
    ...
    *outLen = inLen;  // ❌ BUG: Treats XTS as stream cipher
    return CRYPT_SUCCESS;
}
```

**Problem**: XTS is called via `MODES_CipherStreamProcess`, which is designed for stream ciphers (CTR, CFB, OFB). However, XTS is a **block cipher mode** that should output block-aligned data.

### Why This Is Wrong

1. **XTS is a block cipher mode** (IEEE 1619)
   - Operates on 16-byte blocks
   - Uses ciphertext stealing for partial blocks
   - Should cache incomplete blocks like CBC/ECB

2. **Documentation requires block alignment**
   - `outLen = (inLen / 16 - 2) * 16` (always multiple of 16)
   - Must reserve 2 blocks for Final

3. **Other block modes do it correctly**
   - CBC uses `MODES_CipherUpdate` (line 136-139 in modes_cbc.c)
   - ECB uses `MODES_CipherUpdate`
   - Both cache incomplete blocks and output block-aligned data

## Proposed Fix

### Solution: Create XTS-Specific Update Function

Create a new function `MODES_XTS_CipherUpdate` that properly handles block alignment and caching, similar to how CBC/ECB work.

### Implementation

#### File: `crypto/modes/src/modes_xts.c`

Add the following function after line 544:

```c
/**
 * @brief XTS-specific Update function that handles block alignment and caching
 * 
 * This function implements the documented behavior:
 * - Outputs block-aligned data (outLen % 16 == 0)
 * - Reserves 2 blocks for Final operation
 * - Caches incomplete blocks for later processing
 * 
 * @param modeCtx XTS mode context
 * @param processFuncs Encrypt/decrypt function pointer
 * @param in Input data
 * @param inLen Input length
 * @param out Output buffer
 * @param outLen Output length (set to actual output bytes)
 * @return int32_t CRYPT_SUCCESS on success, error code otherwise
 */
static int32_t MODES_XTS_CipherUpdate(MODES_XTS_Ctx *modeCtx, void *processFuncs,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    int32_t ret;
    uint32_t blockSize = modeCtx->xtsCtx.blockSize;
    uint32_t totalLen = modeCtx->dataLen + inLen;
    
    // Check for overflow
    if (totalLen < modeCtx->dataLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_TOO_LONG);
        return CRYPT_EAL_BUFF_LEN_TOO_LONG;
    }
    
    // Check output buffer size
    if (*outLen < totalLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_EAL_BUFF_LEN_NOT_ENOUGH;
    }
    
    // If total data is less than 2 blocks, cache everything
    if (totalLen < 2 * blockSize) {
        if (inLen > 0) {
            if (memcpy_s(modeCtx->data + modeCtx->dataLen, 
                         EAL_MAX_BLOCK_LENGTH - modeCtx->dataLen, 
                         in, inLen) != EOK) {
                BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
                return CRYPT_SECUREC_FAIL;
            }
            modeCtx->dataLen += inLen;
        }
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    
    // Calculate how many complete blocks we can output
    // Reserve 2 blocks for Final as per documentation
    uint32_t completeBlocks = totalLen / blockSize;
    uint32_t blocksToProcess = (completeBlocks >= 2) ? (completeBlocks - 2) : 0;
    uint32_t bytesToProcess = blocksToProcess * blockSize;
    
    if (bytesToProcess == 0) {
        // Not enough data to output, cache everything
        if (inLen > 0) {
            if (memcpy_s(modeCtx->data + modeCtx->dataLen,
                         EAL_MAX_BLOCK_LENGTH - modeCtx->dataLen,
                         in, inLen) != EOK) {
                BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
                return CRYPT_SECUREC_FAIL;
            }
            modeCtx->dataLen += inLen;
        }
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    
    // Process cached data first, if any
    uint8_t *tmpOut = out;
    uint32_t processedLen = 0;
    
    if (modeCtx->dataLen > 0) {
        // Combine cached data with new data
        uint8_t combinedData[EAL_MAX_BLOCK_LENGTH * 2];  // Max 2 blocks cached
        
        if (memcpy_s(combinedData, sizeof(combinedData), 
                     modeCtx->data, modeCtx->dataLen) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        if (memcpy_s(combinedData + modeCtx->dataLen, 
                     sizeof(combinedData) - modeCtx->dataLen,
                     in, bytesToProcess - modeCtx->dataLen) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        
        // Process the combined data
        ret = ((CipherStreamProcess)processFuncs)(&modeCtx->xtsCtx, combinedData, 
                                                   tmpOut, bytesToProcess);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            (void)memset_s(combinedData, sizeof(combinedData), 0, sizeof(combinedData));
            return ret;
        }
        (void)memset_s(combinedData, sizeof(combinedData), 0, sizeof(combinedData));
        
        processedLen = bytesToProcess;
        tmpOut += bytesToProcess;
        
        // Update input pointer and length
        in += (bytesToProcess - modeCtx->dataLen);
        inLen -= (bytesToProcess - modeCtx->dataLen);
        modeCtx->dataLen = 0;
    } else {
        // No cached data, process directly from input
        ret = ((CipherStreamProcess)processFuncs)(&modeCtx->xtsCtx, in, tmpOut, bytesToProcess);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        
        processedLen = bytesToProcess;
        tmpOut += bytesToProcess;
        in += bytesToProcess;
        inLen -= bytesToProcess;
    }
    
    // Cache remaining data
    if (inLen > 0) {
        if (memcpy_s(modeCtx->data, EAL_MAX_BLOCK_LENGTH, in, inLen) != EOK) {
            BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
            return CRYPT_SECUREC_FAIL;
        }
        modeCtx->dataLen = inLen;
    }
    
    *outLen = processedLen;
    return CRYPT_SUCCESS;
}
```

#### Update `MODES_XTS_Update` function

Replace the current implementation (line 444-448):

```c
int32_t MODES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, 
                          uint8_t *out, uint32_t *outLen)
{
    return MODES_XTS_CipherUpdate(modeCtx, 
        modeCtx->enc ? MODES_XTS_Encrypt : MODES_XTS_Decrypt,
        in, inLen, out, outLen);
}
```

#### Update `AES_XTS_Update` function in `crypto/modes/src/asm_aes_xts.c`

Replace line 56-60:

```c
int32_t AES_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, 
                        uint8_t *out, uint32_t *outLen)
{
    return MODES_XTS_CipherUpdate(modeCtx,
        modeCtx->enc ? MODES_AES_XTS_Encrypt : MODES_AES_XTS_Decrypt,
        in, inLen, out, outLen);
}
```

#### Update `SM4_XTS_Update` function in `crypto/modes/src/asm_sm4_xts.c`

Replace line 40-44:

```c
int32_t SM4_XTS_Update(MODES_XTS_Ctx *modeCtx, const uint8_t *in, uint32_t inLen, 
                        uint8_t *out, uint32_t *outLen)
{
    return MODES_XTS_CipherUpdate(modeCtx,
        modeCtx->enc ? MODES_SM4_XTS_Encrypt : MODES_SM4_XTS_Decrypt,
        in, inLen, out, outLen);
}
```

#### Update `MODES_XTS_Final` function

The Final function needs to process the cached data:

```c
int32_t MODES_XTS_Final(MODES_XTS_Ctx *modeCtx, uint8_t *out, uint32_t *outLen)
{
    if (modeCtx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Process any remaining cached data
    if (modeCtx->dataLen > 0) {
        int32_t ret;
        if (modeCtx->enc) {
            ret = MODES_XTS_Encrypt(&modeCtx->xtsCtx, modeCtx->data, out, modeCtx->dataLen);
        } else {
            ret = MODES_XTS_Decrypt(&modeCtx->xtsCtx, modeCtx->data, out, modeCtx->dataLen);
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        *outLen = modeCtx->dataLen;
        modeCtx->dataLen = 0;
    } else {
        *outLen = 0;
    }
    
    return CRYPT_SUCCESS;
}
```

## Alternative Simpler Fix

If the above is too complex, a simpler fix is to just ensure block alignment without the 2-block reservation:

```c
int32_t MODES_XTS_Update_Simple(MODES_XTS_Ctx *modeCtx, void *processFuncs,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    uint32_t blockSize = modeCtx->xtsCtx.blockSize;
    uint32_t totalLen = modeCtx->dataLen + inLen;
    
    // Calculate complete blocks to output
    uint32_t completeBlocks = totalLen / blockSize;
    uint32_t bytesToProcess = completeBlocks * blockSize;
    
    if (bytesToProcess == 0) {
        // Cache all data
        if (inLen > 0) {
            memcpy(modeCtx->data + modeCtx->dataLen, in, inLen);
            modeCtx->dataLen += inLen;
        }
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    
    // Process complete blocks only
    // ... (similar to CBC implementation)
    
    *outLen = bytesToProcess;  // Always block-aligned!
    return CRYPT_SUCCESS;
}
```

## Testing the Fix

After implementing the fix:

1. **Run the failing test**:
   ```bash
   ./rapidcheck_cipher_update_test xts_outlen_multiple_of_blocksize
   ```
   Expected: **PASS**

2. **Run the unit test**:
   ```bash
   bash testcode/script/execute_sdv.sh SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC002
   ```
   Expected: **PASS**

3. **Run all XTS tests**:
   ```bash
   bash testcode/script/execute_sdv.sh test_suite_sdv_eal_sm4
   ```

4. **Run OpenSSL differential tests**:
   ```bash
   ./rapidcheck_aes_openssl_ref_test openssl_xts128_32bytes
   ```

## Benefits of This Fix

1. ✅ **Fixes the bug**: `outLen` will always be block-aligned
2. ✅ **Matches documentation**: Implements the documented 2-block reservation
3. ✅ **Consistent with other modes**: Similar to CBC/ECB implementation
4. ✅ **Uses existing infrastructure**: Leverages `modeCtx->data` and `modeCtx->dataLen`
5. ✅ **Maintains XTS semantics**: Still uses ciphertext stealing for partial blocks

## Potential Issues

1. **Breaking change**: Applications expecting `outLen == inLen` may break
2. **Performance**: Additional memory copies for caching
3. **Complexity**: More complex than current stream cipher approach

## Recommendation

**Implement the full fix** (not the simple version) because:
- It matches the documented API contract
- It's consistent with block cipher semantics
- It reserves 2 blocks for Final as documented
- It's similar to proven CBC/ECB implementation

The breaking change is acceptable because the current behavior is a **bug** that violates the API contract.