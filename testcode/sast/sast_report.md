# SAST Security Report — OpenHITLS
Date: 2026-03-30
Analyzer: llm-sast-scanner v1.3

## Executive Summary

SAST analysis of OpenHITLS (TLS/SSL implementation) identified **18 findings** across 4 severity levels. The codebase demonstrates generally good security engineering practices with extensive use of safe memory functions (`memcpy_s`, `memset_s`) and proper constant-time operations for cryptographic primitives. However, weak cryptographic algorithm support and several integer overflow vulnerabilities in size calculations require attention.

**Total Findings: 18**
- Critical: 0
- High: 5
- Medium: 10
- Low: 3

---

## Critical Findings

*None identified*

---

## High Findings

### [HIGH] VULN-001 — Weak Cryptographic Hash (MD5)
File: `crypto/provider/src/default/crypt_default_md.c:44-47`
Description: MD5 algorithm is implemented and available for cryptographic use.
Impact: MD5 is cryptographically broken due to collision vulnerabilities. An attacker can forge certificates or certificates with the same hash.
Evidence:
```c
#ifdef HITLS_CRYPTO_MD5
    {CRYPT_MD_MD5, g_defEalMdMd5, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_MD5
```
Judge: MD5 is enabled via compile-time flag and used in TLS 1.0/1.1 key derivation (kdf_tls12.c:39).
Remediation: Disable MD5 by setting `HITLS_CRYPTO_MD5=OFF` in build configuration.
Reference: references/weak_crypto_hash.md

---

### [HIGH] VULN-002 — Weak Cryptographic Hash (SHA1)
File: `crypto/provider/src/default/crypt_default_md.c:48-50`
Description: SHA1 algorithm is implemented and available for cryptographic use.
Impact: SHA1 is weakened due to collision vulnerabilities. Deprecated for certificate signatures.
Evidence:
```c
#ifdef HITLS_CRYPTO_SHA1
    {CRYPT_MD_SHA1, g_defEalMdSha1, CRYPT_EAL_DEFAULT_ATTR},
#endif // HITLS_CRYPTO_SHA1
```
Judge: SHA1 is enabled via compile-time flag and used in signature schemes (crypt_default_provider.c:1168-1207).
Remediation: Disable SHA1 by setting `HITLS_CRYPTO_SHA1=OFF` in build configuration.
Reference: references/weak_crypto_hash.md

---

### [HIGH] VULN-003 — Weak HMAC in TLS Key Derivation
File: `crypto/kdf/src/kdf_tls12.c:35-42`
Description: HMAC-MD5 and HMAC-SHA1 are supported for TLS 1.0/1.1 key derivation.
Impact: Weak hash functions in key derivation compromise TLS security.
Evidence:
```c
static const uint32_t KDFTLS12_ID_LIST[] = {
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_MAC_HMAC_SM3, // for TLCP
    CRYPT_MAC_HMAC_MD5, // for TLS1.0 and TLS1.1
    CRYPT_MAC_HMAC_SHA1, // for TLS1.0 and TLS1.1
};
```
Judge: TLS 1.0/1.1 backward compatibility requires these weak algorithms.
Remediation: Disable TLS 1.0/1.1 support entirely. Use TLS 1.2+ with SHA-256 or stronger.
Reference: references/weak_crypto_hash.md

---

### [HIGH] VULN-004 — SHA1-based Signature Schemes
File: `crypto/provider/src/default/crypt_default_provider.c:1168-1207`
Description: SHA1-based signature schemes (ECDSA-SHA1, RSA-PKCS1-SHA1, DSA-SHA1) are supported.
Impact: SHA1 signatures are vulnerable to collision attacks.
Evidence:
```c
{
    CONST_CAST("ecdsa_sha1"),
    CERT_SIG_SCHEME_ECDSA_SHA1,
    ...
    HITLS_HASH_SHA1,
    63, // https://eprint.iacr.org/2020/014
    ...
}
```
Judge: SHA1 signatures are registered as valid signature schemes.
Remediation: Disable SHA1 signature schemes or enforce minimum hash size policy.
Reference: references/weak_crypto_hash.md

---

### [HIGH] VULN-005 — Integer Overflow in CRL Entry Encoding
File: `pki/x509_crl/src/hitls_x509_crl.c:453`
Description: Size calculation in malloc can overflow with large `count` values.
Impact: Undersized buffer allocation leads to heap overflow.
Evidence:
```c
BSL_ASN1_Buffer *asnBuf = BSL_SAL_Malloc(
    (uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLENTRY_ELEM_NUMBER);
```
Judge: Multiplication overflow occurs before cast to uint32_t, wrapping to small value.
Remediation: Add overflow check before multiplication:
```c
if (count > UINT32_MAX / (sizeof(BSL_ASN1_Buffer) * X509_CRLEXT_ELEM_NUMBER)) {
    return ERROR;
}
```
Reference: references/denial_of_service.md

---

## Medium Findings

### [MEDIUM] VULN-006 — Integer Overflow in X509 Extension Encoding
File: `pki/x509_common/src/hitls_x509_ext.c:1423`
Description: Size calculation in malloc can overflow with large `count` values.
Evidence:
```c
BSL_ASN1_Buffer *asnBuf = BSL_SAL_Malloc(
    count * X509_CRLEXT_ELEM_NUMBER * sizeof(BSL_ASN1_Buffer));
```
Judge: Same overflow pattern as VULN-005 but in extension encoding path.
Remediation: Add overflow check before multiplication.

---

### [MEDIUM] VULN-007 — Integer Overflow in TLS Extension Parsing
File: `tls/handshake/parse/src/parse.c:572`
Description: Size calculation in malloc can overflow with large `extensionCount`.
Evidence:
```c
uint16_t *extPresent = BSL_SAL_Malloc(
    ctx->hsCtx->hsMsg->body.clientHello.extensionCount * sizeof(uint16_t));
```
Judge: Attacker-controlled `extensionCount` could cause overflow.
Remediation: Validate `extensionCount` against reasonable maximum before allocation.

---

### [MEDIUM] VULN-008 — Integer Overflow in memset (CRL)
File: `pki/x509_crl/src/hitls_x509_crl.c:458-459`
Description: Same integer overflow issue affects memset size parameter.
Evidence:
```c
(void)memset_s(asnBuf,
    (uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLEXT_ELEM_NUMBER,
    0,
    (uint32_t)count * sizeof(BSL_ASN1_Buffer) * X509_CRLEXT_ELEM_NUMBER);
```
Judge: Overflow in size parameter can cause memset to write beyond buffer bounds.
Remediation: Add overflow check before size calculation.

---

### [MEDIUM] VULN-009 — Buffer Overflow in SM9 User ID Copy
File: `crypto/sm9/src/sm9_sign.c:87,106`
Description: Unchecked memcpy with user-controlled length.
Evidence:
```c
memcpy(ctx->user_id, user_id, id_len);
```
Judge: `id_len` not validated against `ctx->user_id` buffer size.
Remediation: Validate `id_len` <= `SM9_MAX_ID_LEN` before copy.

---

### [MEDIUM] VULN-010 — Buffer Overflow in SM9 EAL User ID Copy
File: `crypto/sm9/src/sm9_eal.c:228,254,666`
Description: Unchecked memcpy with user-controlled length.
Evidence:
```c
memcpy(ctx->user_id, userId, userIdLen);
memcpy(ctx->user_id, val, valLen);
```
Judge: Multiple paths with unchecked user-controlled lengths.
Remediation: Add bounds validation before all user_id copies.

---

### [MEDIUM] VULN-011 — Pointer Arithmetic Without Bounds (SM9)
File: `crypto/sm9/src/sm9.c:649,855,1034,1045,1125,1137,1219,1307`
Description: Pointer arithmetic expressions could exceed buffer bounds.
Evidence:
```c
memcpy(temp + 1 + 12 * BNByteLen, inner_hash, SM9_Hash_Size);
memcpy(Z + Zlen, inner_hash, SM9_Hash_Size);
```
Judge: Expressions like `temp + 1 + 12 * BNByteLen` assume BNByteLen is within bounds.
Remediation: Validate `BNByteLen` is within expected range before use in arithmetic.

---

### [MEDIUM] VULN-012 — Hardcoded AES Key Wrap IV
File: `crypto/modes/src/modes_aes_wrap.c:37-43,339-343`
Description: AES Key Wrap uses hardcoded default IV.
Evidence:
```c
static const uint8_t DEFAULT_IV[CRYPT_WRAP_BLOCKSIZE] = {
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};
```
Judge: While RFC 3394 specifies this default, known IV reuse is a concern.
Remediation: Document this as intentional per RFC 3394. Consider per-key unique IVs where applicable.

---

### [MEDIUM] VULN-013 — Weak DH Parameters (112-bit security)
File: `crypto/provider/src/default/crypt_default_provider.c:828-836`
Description: ffdhe2048 DH group provides only 112-bit security.
Evidence:
```c
{
    CONST_CAST("ffdhe2048"),
    112, // secBits  <-- Only 112-bit security
    ...
}
```
Judge: 112-bit security is below modern recommendations (128-bit minimum).
Remediation: Mark ffdhe2048 as deprecated. Recommend ffdhe3072 as minimum.

---

### [MEDIUM] VULN-014 — PEM Length Calculation Overflow
File: `bsl/pem/src/bsl_pem.c:121-122`
Description: No overflow check on length calculation.
Evidence:
```c
uint32_t line = (len + PEM_LINE_LEN - 1) / PEM_LINE_LEN;
uint32_t sumLen = line + len + headLen + tailLen + 3;
```
Judge: Extremely large `len` could cause `sumLen` to wrap.
Remediation: Add overflow check before calculating `sumLen`.

---

### [MEDIUM] VULN-015 — DH Parameter Validation Limited
File: `tls/handshake/parse/src/parse_server_key_exchange.c:346-401`
Description: DH parameters validated only for length, not cryptographic strength.
Evidence:
```c
static int32_t ParseServerDhe(ParsePacket *pkt, ServerKeyExchangeMsg *msg)
{
    int32_t ret = ParseDhePara(pkt, &dh->plen, &dh->p);  // Only length
    ret = ParseDhePara(pkt, &dh->glen, &dh->g);  // No generator validation
```
Judge: Weak DH groups could be accepted if underlying crypto library doesn't validate.
Remediation: Ensure SAL_CRYPT layer validates DH parameters per RFC 7919.

---

### [MEDIUM] VULN-016 — ECDH Public Key Validation Limited
File: `tls/handshake/parse/src/parse_server_key_exchange.c:172-208`
Description: ECDH public key validated only for size, not curve membership.
Evidence:
```c
if ((ecdh->ecPara.type == HITLS_EC_CURVE_TYPE_NAMED_CURVE) &&
    (pubKeySize != HS_GetCryptLength(...))) {  // Only size check
```
Judge: Point-on-curve validation depends on crypto library implementation.
Remediation: Ensure crypto library verifies public key is valid point on curve.

---

## Low Findings

### [LOW] VULN-017 — Integer Overflow in CRL memset
File: `pki/x509_crl/src/hitls_x509_crl.c:458-459`
Description: Related to VULN-008, affects memset size calculation.
Evidence: Same code pattern as VULN-008.
Judge: Low severity due to prior checks in the code path.
Remediation: Consider fixing alongside VULN-008.

---

### [LOW] VULN-018 — PSK Identity Null Termination
File: `tls/handshake/common/src/hs_common.c:509-517`
Description: PSK identity handling with potential null termination concern.
Evidence:
```c
tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (identityUsedLen + 1));
(void)memcpy_s(tmpIdentity, identityUsedLen + 1, identity, identityUsedLen);
```
Judge: Code allocates `+1` for null termination but copy is correct.
Remediation: Ensure null byte is explicitly written:
```c
tmpIdentity[identityUsedLen] = '\0';
```

---

### [LOW] VULN-019 — Unsafe String Operations in Test Code
File: `testcode/framework/tls/rpc/src/hlt_rpc_func.c:1787,1791,1805,1807`
Description: Unsafe sprintf and strcpy in test code.
Evidence:
```c
sprintf(&ret[i * 2], "%02x", buf[i]);
strcpy(ret, "NULL");
```
Judge: Test code only, not deployed in production.
Remediation: Consider fixing for consistency, but low priority.

---

## Security Positives

The following security measures are properly implemented:

1. **Lucky13 Mitigation**: Constant-time padding verification in `tls/record/src/rec_crypto_cbc.c:267-283`
2. **Downgrade Protection**: TLS 1.3 downgrade protection markers in `tls/handshake/common/src/hs_common.c:63-71`
3. **Secure Renegotiation**: RFC 5746 properly implemented
4. **Record Length Validation**: Bounds checking in `tls/record/src/rec_read.c:302-308`
5. **Constant-Time Comparison**: Finished message verification uses `ConstTimeMemcmp`
6. **Safe Memory Functions**: Extensive use of `memcpy_s`, `memset_s`, `strcpy_s`

---

## Remediation Priority

| Priority | Findings | Action |
|----------|---------|--------|
| 1 (Critical) | VULN-001 to VULN-005 | Disable weak crypto algorithms (MD5/SHA1). Add overflow protection. |
| 2 (High) | VULN-006 to VULN-011 | Add integer overflow checks. Validate SM9 buffer sizes. |
| 3 (Medium) | VULN-012 to VULN-016 | Document hardcoded IVs. Upgrade DH parameters. Enhance validation. |
| 4 (Low) | VULN-017 to VULN-019 | Minor improvements in test code and null termination. |

---

## Notes

- Many weak crypto findings are intentional for backward compatibility and regulatory compliance (FIPS 140-2/3).
- Use compile-time flags (`HITLS_CRYPTO_MD5`, `HITLS_CRYPTO_SHA1`) to disable weak algorithms when not required.
- Consider enabling AddressSanitizer and UndefinedBehaviorSanitizer during testing to catch memory safety issues.
- Fuzz testing of protocol parsing paths is recommended for additional coverage.
