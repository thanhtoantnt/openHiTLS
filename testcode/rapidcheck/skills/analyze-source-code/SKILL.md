---
name: analyze-source-code
description: Extract testable properties from C/C++ source code for property-based testing. Use when analyzing crypto libraries, APIs with serialization/validation patterns, or when starting PBT synthesis for a new codebase.
---

# Source Code Analysis for PBT

Analyze C/C++ source code to extract testable properties for property-based testing synthesis.

## When to Invoke

**Invoke this skill when:**

- Starting PBT synthesis for a new codebase or module
- Analyzing crypto libraries (AES, SHA, HMAC, etc.)
- Reviewing APIs with serialization/validation patterns
- Extracting properties from header files
- Understanding API contracts for test generation
- User asks to "analyze source code for properties" or "extract testable properties"

**Priority by code type:**

| Code Type | Properties | Priority |
|-----------|------------|----------|
| Crypto (AES, SM4, ChaCha20) | Roundtrip, key sensitivity, determinism | CRITICAL |
| Hash (SHA, SM3, MD5) | Determinism, fixed output, avalanche | CRITICAL |
| MAC (HMAC) | Key/message sensitivity, tag verification | CRITICAL |
| Encode/Decode (Base64) | Roundtrip, valid charset | HIGH |
| Big Number (BN) | Arithmetic properties, overflow | HIGH |
| Validation/Normalization | Idempotence, valid after normalize | MEDIUM |

## When NOT to Use

Do NOT use this skill for:
- Non-C/C++ code (use language-specific analyzers)
- Simple getters/setters without logic
- UI/presentation code
- Code without clear API boundaries

## Analysis Process

### Step 1: Discover Source Files

Find relevant source files in the target path:

```
1. Header files (.h, .hpp) - Focus on public API definitions
2. Source files (.c, .cpp) - Look for implementation patterns
3. Start with public API headers
```

### Step 2: Extract Function Signatures

For each function, extract:

```yaml
Function:
  name: FunctionName
  file: path/to/file.h
  line: 45
  parameters:
    - name: param_name
      type: const uint8_t*
      constraints: [non_null, size=16]
      is_pointer: true
      is_const: true
  return_value:
    type: int32_t
    success_values: [CRYPT_SUCCESS]
    error_values: [CRYPT_NULL_INPUT, CRYPT_PARAM_ERROR]
  is_public: true
  api_pattern: Init/Update/Final
```

### Step 3: Detect Parameter Constraints

Look for these patterns:

**Null pointer checks:**
```c
if (ptr == NULL) return ERROR;
if (!ptr) return ERROR;
```
→ Constraint: `non_null`

**Size checks:**
```c
if (len != 16) return ERROR;
if (len < 0 || len > MAX) return ERROR;
```
→ Constraint: `size=N`, `range=min-max`

**Enum/value checks:**
```c
if (type != AES_128 && type != AES_256) return ERROR;
```
→ Constraint: `values=[AES_128, AES_256]`

### Step 4: Identify API Patterns

| Pattern | Functions | Properties |
|---------|-----------|------------|
| Init/Update/Final | `X_Init`, `X_Update`, `X_Final` | Streaming, incremental |
| Create/Destroy | `X_Create`, `X_Destroy` | Resource management |
| Encode/Decode | `X_Encode`, `X_Decode` | Roundtrip |
| Encrypt/Decrypt | `X_Encrypt`, `X_Decrypt` | Roundtrip, key sensitivity |
| Set/Get | `X_SetY`, `X_GetY` | Configuration consistency |

### Step 5: Generate Properties

For each function, generate testable properties:

**Correctness:**
- Roundtrip: `decrypt(encrypt(x, k), k) == x`
- Inverse: `decode(encode(x)) == x`

**Security:**
- Key sensitivity: `encrypt(k1, p) != encrypt(k2, p)` when `k1 != k2`
- Determinism: `encrypt(k, p) == encrypt(k, p)`

**Safety:**
- Null handling: Function handles null inputs
- Boundary conditions: Edge cases handled

## Property Catalog by API Type

### Cipher (AES, SM4, ChaCha20)

| Property | Formula | Priority |
|----------|---------|----------|
| Roundtrip | `decrypt(encrypt(p, k), k) == p` | CRITICAL |
| Key sensitivity | `k1 != k2 → encrypt(k1, p) != encrypt(k2, p)` | CRITICAL |
| Determinism | `encrypt(k, p) == encrypt(k, p)` | HIGH |
| Size preservation | `len(encrypt(p)) == len(p)` | HIGH |
| Plaintext sensitivity | `p1 != p2 → encrypt(k, p1) != encrypt(k, p2)` | HIGH |

### Hash (SHA, SM3, MD5)

| Property | Formula | Priority |
|----------|---------|----------|
| Determinism | `hash(x) == hash(x)` | CRITICAL |
| Fixed output | `len(hash(x)) == N` | CRITICAL |
| Avalanche | Small change → different hash | HIGH |
| Incremental | `hash(a+b) == hash(a) then hash(b)` | MEDIUM |

### MAC (HMAC)

| Property | Formula | Priority |
|----------|---------|----------|
| Key sensitivity | `k1 != k2 → hmac(k1, m) != hmac(k2, m)` | CRITICAL |
| Message sensitivity | `m1 != m2 → hmac(k, m1) != hmac(k, m2)` | CRITICAL |
| Determinism | `hmac(k, m) == hmac(k, m)` | HIGH |
| Tag verification | Wrong tag → verification fails | HIGH |

### Encoding (Base64)

| Property | Formula | Priority |
|----------|---------|----------|
| Roundtrip | `decode(encode(x)) == x` | CRITICAL |
| Valid charset | Output contains only valid chars | HIGH |
| Size formula | `len(encode(x)) == ceil(len(x)/3)*4` | MEDIUM |

### Big Number (BN)

| Property | Formula | Priority |
|----------|---------|----------|
| Add/Sub inverse | `sub(add(a, b), b) == a` | HIGH |
| Mul/Div inverse | `div(mul(a, b), b) == a` | HIGH |
| Commutativity | `add(a, b) == add(b, a)` | MEDIUM |

## Output Format

Return analysis as structured YAML:

```yaml
source_path: /path/to/analyzed/code
functions:
  - name: CRYPT_AES_Encrypt
    file: crypto/aes/include/crypt_aes.h
    line: 45
    parameters:
      - name: key
        type: CRYPT_AES_Key*
        constraints: [non_null]
      - name: plaintext
        type: const uint8_t*
        constraints: [non_null, size_multiple=16]
      - name: len
        type: uint32_t
        constraints: [positive, multiple=16]
    return_value:
      type: int32_t
      success_values: [CRYPT_SUCCESS]
      error_values: [CRYPT_NULL_INPUT]
    is_public: true
    api_pattern: null
    properties:
      - id: P001
        name: aes_encrypt_roundtrip
        type: correctness
        priority: critical
        description: "AES encryption followed by decryption returns original"
        function: CRYPT_AES_Encrypt/CRYPT_AES_Decrypt
        precondition: "key != null && plaintext != null && len > 0"
        postcondition: "decrypt(encrypt(p, k), k) == p"
        
      - id: P002
        name: aes_key_sensitivity
        type: security
        priority: critical
        description: "Different keys produce different ciphertexts"
        function: CRYPT_AES_Encrypt
        precondition: "k1 != k2"
        postcondition: "encrypt(k1, p) != encrypt(k2, p)"

data_types:
  - name: CRYPT_AES_Key
    type: struct
    file: crypto/aes/include/crypt_aes.h
    line: 30
    fields:
      - name: bits
        type: uint32_t
        constraints: [values=[128, 192, 256]]
    invariants:
      - "rounds = bits/32 + 6"
```

## Example Usage

**Analyze a single header:**
```
Analyze the source code at crypto/aes/include/crypt_aes.h and extract testable properties for property-based testing.
```

**Analyze a directory:**
```
Analyze all source files in crypto/ directory and extract properties for PBT synthesis.
```

**Focus on specific functions:**
```
Analyze CRYPT_AES_Encrypt and CRYPT_AES_Decrypt from crypto/aes/ and identify roundtrip properties.
```

## Integration with PBT Pipeline

This skill is step 1 in the PBT synthesis pipeline:

```
1. analyze-source-code (this skill)
   ↓ Extract properties from source code
   
2. analyze-merge-request
   ↓ Extract properties from MRs/PRs
   
3. extract-properties
   ↓ Merge and prioritize
   
4. generate-pbt
   ↓ Generate RapidCheck tests
   
5. validate-pbt
   ↓ Compile and run
```

## Checklist Before Finishing

- [ ] All public API functions identified
- [ ] Parameter constraints extracted from code patterns
- [ ] Return value patterns documented
- [ ] API patterns recognized (Init/Update/Final, etc.)
- [ ] Properties generated for each function
- [ ] Properties prioritized by security impact
- [ ] Data types documented with invariants

## Red Flags

- **Missing crypto functions** - These are highest priority
- **Only extracting names** - Must extract constraints too
- **Ignoring error paths** - Every error is a test case
- **Missing API patterns** - Init/Update/Final needs incremental tests
- **No security properties** - Crypto needs key sensitivity tests