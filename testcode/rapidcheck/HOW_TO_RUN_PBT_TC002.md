# How to Build and Run the New Unit Test

## Test Added

**Test Name**: `SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC002`

**Purpose**: Verify that XTS mode Update outputs block-aligned data (outLen % 16 == 0)

**Location**: 
- Test code: `testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.c`
- Test data: `testcode/sdv/testcase/crypto/sm4/test_suite_sdv_eal_sm4.data`

## Build Instructions

### Step 1: Build openHiTLS Libraries (if not already built)

```bash
cd /Users/thanhtoantnt/workspace/pbt/openHiTLS
bash testcode/script/build_hitls.sh
```

This will build the required libraries in the `build/` directory.

### Step 2: Build the SDV Test Suite

```bash
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_eal_sm4
```

This will:
1. Generate the test file from `test_suite_sdv_eal_sm4.c` and `test_suite_sdv_eal_sm4.data`
2. Compile the test executable
3. Place the executable in `testcode/output/`

**Note**: If you encounter an error like "missing end case tag" or "scan function failed", it means the test generation tool failed. This is expected because the test file needs to be regenerated.

### Step 3: Alternative Manual Build (if script fails)

If the build script fails, you can try:

```bash
# Clean and rebuild
cd testcode/output
rm -f test_suite_sdv_eal_sm4.c test_suite_sdv_eal_sm4

# Regenerate test file
cd /Users/thanhtoantnt/workspace/pbt/openHiTLS
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_eal_sm4
```

## Run Instructions

### Option 1: Run the Specific Test

```bash
bash testcode/script/execute_sdv.sh SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC002
```

### Option 2: Run All SM4 Tests

```bash
bash testcode/script/execute_sdv.sh test_suite_sdv_eal_sm4
```

### Option 3: Run the Test Executable Directly

```bash
cd testcode/output
./test_suite_sdv_eal_sm4 SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC002
```

## Expected Result

The test will **FAIL** with an assertion error:

```
ASSERT_TRUE(outLen % 16 == 0) failed
Expected: 0 (true)
Actual: 33 % 16 = 1 (false)
```

This demonstrates the bug where XTS Update outputs non-block-aligned data.

## Test Details

### Input Values (from RapidCheck counterexample)

- **Key**: 32 bytes
  ```
  {0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 1, 0}
  ```

- **IV**: 16 bytes (all zeros)

- **Input**: 33 bytes (all zeros)

### Expected Behavior

- `outLen % 16 == 0` (block-aligned output)
- Possible values: 0, 16, or 32 bytes

### Actual Behavior (Bug)

- `outLen = 33` (not block-aligned)
- This violates block cipher semantics

## Troubleshooting

### Problem: "missing end case tag" error

**Solution**: This is a known issue with the test generation tool. The test file structure is correct, but the generation tool may fail. Try:

1. Check that `/* END_CASE */` is present after the test function
2. Ensure the test name in the .data file matches the function name
3. Try rebuilding with verbose output:
   ```bash
   bash testcode/script/build_sdv.sh verbose run-tests=test_suite_sdv_eal_sm4
   ```

### Problem: Test executable not found

**Solution**: The test needs to be generated first. Run:
```bash
bash testcode/script/build_sdv.sh run-tests=test_suite_sdv_eal_sm4
```

### Problem: Test passes instead of failing

**Solution**: This would indicate the bug has been fixed! Check:
1. Verify you're testing the correct version
2. Check the implementation in `crypto/modes/src/modes.c`
3. Look for `*outLen = inLen;` at line 542

## Related Tests

- **SDV_CRYPTO_SM4_XTS_UPDATE_PBT_TC001**: Tests that XTS reserves 2 blocks for Final (also fails)
- **test_xts_outlen_multiple_of_blocksize**: RapidCheck PBT test that found this bug
- **test_xts_32_bytes**: RapidCheck PBT test for the 2-block reservation bug

## Analysis Documents

- `testcode/rapidcheck/XTS_BUG_ANALYSIS.md` - Analysis of the 2-block reservation bug
- `testcode/rapidcheck/XTS_BLOCK_ALIGNMENT_ANALYSIS.md` - Analysis of the block alignment bug

## Next Steps

1. Run the test to confirm the failure
2. Review the analysis documents to understand the bug
3. Fix the implementation in `crypto/modes/src/modes.c`
4. Re-run the test to verify the fix
5. Run all XTS tests to ensure no regressions