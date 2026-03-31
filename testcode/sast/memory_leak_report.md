# Memory Leak Analysis Report — OpenHITLS
Date: 2026-03-30
Analyzer: Manual Code Review

## Executive Summary

Analysis identified **12 memory leak vulnerabilities** across the codebase. The most critical issues are in TLS handshake parsing functions where linked list nodes are allocated in loops but not freed when errors occur mid-parsing.

**Total Findings: 12**
- High: 5
- Medium: 5
- Low: 2

---

## High Severity Findings

### [HIGH] LEAK-001 — Memory Leak in ParseIdentities Error Paths
**File:** `tls/handshake/parse/src/parse_extensions_server.c:311-364`

**Description:** When parsing PSK identities in a loop, if an error occurs after nodes have been added to the linked list, the function returns without freeing the already-allocated nodes.

**Vulnerable Code:**
```c
int32_t ParseIdentities(TLS_Ctx *ctx, PreSharedKey *preSharedKey, const uint8_t *buf, uint32_t bufLen)
{
    while (bufOffset + sizeof(uint16_t) < bufLen) {
        PreSharedKey *node = (PreSharedKey *)BSL_SAL_Calloc(1, sizeof(PreSharedKey));
        if (node == NULL) {
            return HITLS_MEMALLOC_FAIL;  // LEAK: preSharedKey list not cleaned
        }
        LIST_ADD_AFTER(&tmp->pskNode, &node->pskNode);
        // ...
        node->identity = (uint8_t *)BSL_SAL_Calloc(1u, (node->identitySize + 1) * sizeof(uint8_t));
        if (node->identity == NULL) {
            return HITLS_MEMALLOC_FAIL;  // LEAK: node already added to list
        }
    }
    if (bufOffset != bufLen) {
        return HITLS_PARSE_INVALID_MSG_LEN;  // LEAK: entire list not cleaned
    }
}
```

**Impact:** Malformed ClientHello messages can cause memory leaks during TLS handshake.

**Remediation:** Add cleanup function to free the linked list on error:
```c
if (ret != HITLS_SUCCESS) {
    CleanPreSharedKeyList(preSharedKey);
    return ret;
}
```

---

### [HIGH] LEAK-002 — Memory Leak in ParseKeyShare Error Paths
**File:** `tls/handshake/parse/src/parse_extensions_server.c:412-463`

**Description:** When parsing key shares in a loop, if an error occurs after KeyShare nodes have been added to the linked list, the function frees `groupSet` but not the already-allocated KeyShare nodes.

**Vulnerable Code:**
```c
int32_t ParseKeyShare(KeyShare *keyshare, const uint8_t *buf, uint32_t bufLen, ALERT_Description *alert)
{
    while (bufOffset + sizeof(uint16_t) + sizeof(uint16_t) < bufLen) {
        KeyShare *tmpNode = (KeyShare *)BSL_SAL_Calloc(1u, sizeof(KeyShare));
        if (tmpNode == NULL) {
            BSL_SAL_FREE(groupSet);
            return HITLS_MEMALLOC_FAIL;  // LEAK: Previously allocated tmpNodes not freed
        }
        LIST_ADD_AFTER(&node->head, &tmpNode->head);
        // ...
        node->keyExchange = (uint8_t *)BSL_SAL_Dump(&buf[bufOffset], node->keyExchangeSize);
        if (node->keyExchange == NULL) {
            BSL_SAL_FREE(groupSet);
            return HITLS_MEMALLOC_FAIL;  // LEAK: All allocated nodes not freed
        }
    }
}
```

**Impact:** Malformed ClientHello messages can cause memory leaks.

**Remediation:** Call `CleanKeyShare(keyshare)` before returning on error.

---

### [HIGH] LEAK-003 — Memory Leak in ParseCerts Error Paths
**File:** `tls/handshake/parse/src/parse_certificate.c:141-175`

**Description:** When parsing certificate chain in a loop, if parsing fails for any certificate or extension, the function returns without freeing the already-parsed certificate items.

**Vulnerable Code:**
```c
int32_t ParseCerts(ParsePacket *pkt, HS_Msg *hsMsg)
{
    while (*pkt->bufOffset < pkt->bufLen) {
        CERT_Item *item = NULL;
        ret = ParseSingleCert(pkt, &item);
        if (ret != HITLS_SUCCESS) {
            return HITLS_PARSE_CERT_ERR;  // LEAK: Previously parsed cert items not freed
        }
        // Add to list...
        ret = ParseCertExtension(pkt, msg, item, msg->certCount);
        if (ret != HITLS_SUCCESS) {
            return ret;  // LEAK: All previously parsed cert items not freed
        }
    }
}
```

**Impact:** Malformed Certificate messages can cause significant memory leaks (certificates can be large).

**Remediation:** Add cleanup to free the certificate linked list on error.

---

### [HIGH] LEAK-004 — Memory Leak in GetPkey (CMVP Self-Test)
**File:** `crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_ecdh.c:55-106`

**Description:** When `*pkeyPub` allocation fails after `*pkeyPrv` succeeds, `*pkeyPrv` is not freed.

**Vulnerable Code:**
```c
static bool GetPkey(void *libCtx, const char *attrName, bool isBob, CRYPT_EAL_PkeyCtx **pkeyPrv,
    CRYPT_EAL_PkeyCtx **pkeyPub, CRYPT_EAL_PkeyPub *pub, CRYPT_EAL_PkeyPrv *prv)
{
    *pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPrv == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    *pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_ECDH, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPub == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);  // LEAK: *pkeyPrv not freed

    // ...
ERR:
    BSL_SAL_FREE(x);
    BSL_SAL_FREE(y);
    return ret;  // pkeyPrv and pkeyPub not freed on error
}
```

**Impact:** Memory leak during CMVP self-test failure.

**Remediation:** Add cleanup for pkey contexts in error path:
```c
ERR:
    BSL_SAL_FREE(x);
    BSL_SAL_FREE(y);
    if (!ret) {
        CRYPT_EAL_PkeyFreeCtx(*pkeyPrv);
        CRYPT_EAL_PkeyFreeCtx(*pkeyPub);
        *pkeyPrv = NULL;
        *pkeyPub = NULL;
    }
    return ret;
```

---

### [HIGH] LEAK-005 — Memory Leak in CheckClientPsk Error Paths
**File:** `tls/handshake/common/src/hs_common.c:474-532`

**Description:** When `pskInfo` is allocated but subsequent allocations fail, `pskInfo` is not freed.

**Vulnerable Code:**
```c
int32_t CheckClientPsk(TLS_Ctx *ctx)
{
    if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
        ctx->hsCtx->kxCtx->pskInfo = (PskInfo *)BSL_SAL_Calloc(1u, sizeof(PskInfo));
        if (ctx->hsCtx->kxCtx->pskInfo == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
    }

    uint8_t *tmpIdentity = (uint8_t *)BSL_SAL_Calloc(1u, (identityUsedLen + 1));
    if (tmpIdentity == NULL) {
        return HITLS_MEMALLOC_FAIL;  // LEAK: pskInfo was allocated but not freed
    }
    // ...
    ctx->hsCtx->kxCtx->pskInfo->psk = (uint8_t *)BSL_SAL_Dump(psk, pskUsedLen);
    if (ctx->hsCtx->kxCtx->pskInfo->psk == NULL) {
        BSL_SAL_FREE(tmpIdentity);
        return HITLS_MEMALLOC_FAIL;  // LEAK: pskInfo was allocated but not freed
    }
}
```

**Impact:** Memory leak during PSK handshake failure.

**Remediation:** Free `pskInfo` in error paths:
```c
if (tmpIdentity == NULL) {
    BSL_SAL_FREE(ctx->hsCtx->kxCtx->pskInfo);
    return HITLS_MEMALLOC_FAIL;
}
```

---

## Medium Severity Findings

### [MEDIUM] LEAK-006 — Memory Leak in ConstructUserPsk
**File:** `tls/handshake/send/src/send_client_hello.c:375-399`

**Description:** When `identity` allocation fails, `userPsk->pskSession` (duplicated session) is not freed.

**Vulnerable Code:**
```c
static UserPskList *ConstructUserPsk(HITLS_Session *sessoin, const uint8_t *identity, uint32_t identityLen,
    uint8_t curIndex)
{
    UserPskList *userPsk = BSL_SAL_Calloc(1, sizeof(UserPskList));
    userPsk->pskSession = HITLS_SESS_Dup(sessoin);
    userPsk->identity = BSL_SAL_Calloc(1, identityLen);
    if (userPsk->identity == NULL) {
        BSL_SAL_FREE(userPsk);  // LEAK: userPsk->pskSession not freed
        return NULL;
    }
}
```

**Remediation:**
```c
if (userPsk->identity == NULL) {
    HITLS_SESS_Free(userPsk->pskSession);
    BSL_SAL_FREE(userPsk);
    return NULL;
}
```

---

### [MEDIUM] LEAK-007 — Potential Double-Free in ParseGeneralName
**File:** `pki/x509_common/src/hitls_x509_ext.c:273-286`

**Description:** If `BSL_LIST_AddElement` fails, `dirNames` is freed but `name->value.data` may point to it, causing potential double-free or use-after-free.

**Vulnerable Code:**
```c
HITLS_X509_GeneralName *name = BSL_SAL_Calloc(1, sizeof(HITLS_X509_GeneralName));
if (name == NULL) {
    BSL_LIST_FREE(dirNames, ...);  // dirNames freed
    return BSL_MALLOC_FAIL;
}
name->type = type;
name->value = value;  // value.data may point to dirNames
ret = BSL_LIST_AddElement(list, name, BSL_LIST_POS_END);
if (ret != BSL_SUCCESS) {
    BSL_LIST_FREE(dirNames, ...);  // dirNames freed again if it was assigned to value.data
    BSL_SAL_Free(name);
}
```

**Remediation:** Check if `dirNames` was assigned to `value.data` before freeing.

---

### [MEDIUM] LEAK-008 — Memory Leak in EncodeX509List
**File:** `pki/cms/src/hitls_cms_signdata.c:700-748`

**Description:** If `encodeFunc` fails during the loop, `asnBuf` may not be freed properly.

**Remediation:** Ensure `FreeAsnList` is called in all error paths.

---

### [MEDIUM] LEAK-009 — Memory Leak in ParseClientSignatureAlgorithms
**File:** `tls/handshake/parse/src/parse_extensions_server.c:97-144`

**Description:** When `BSL_SAL_Dump` fails for `signatureAlgorithms`, the already-assigned `msg->extension.content.signatureAlgorithms` is not freed.

**Remediation:** Free `signatureAlgorithms` before returning error.

---

### [MEDIUM] LEAK-010 — Memory Leak in HS_KX_PskCheck
**File:** `tls/handshake/common/src/hs_kx.c:700-740`

**Description:** Similar pattern to LEAK-005 - `pskInfo` allocated but not freed on subsequent allocation failures.

---

## Low Severity Findings

### [LOW] LEAK-011 — NULL Pointer Dereference in SM9_NewCtx
**File:** `crypto/sm9/src/sm9_sign.c:36-41`

**Description:** Uses `malloc` instead of `BSL_SAL_Malloc`. If `malloc` fails, `SM9_ResetCtx(ctx)` dereferences NULL pointer.

**Vulnerable Code:**
```c
SM9_Ctx* SM9_NewCtx(void)
{
    SM9_Ctx *ctx = (SM9_Ctx*)malloc(sizeof(SM9_Ctx));
    SM9_ResetCtx(ctx);  // CRASH if malloc returns NULL
    return ctx;
}
```

**Remediation:**
```c
SM9_Ctx* SM9_NewCtx(void)
{
    SM9_Ctx *ctx = (SM9_Ctx*)BSL_SAL_Malloc(sizeof(SM9_Ctx));
    if (ctx == NULL) {
        return NULL;
    }
    SM9_ResetCtx(ctx);
    return ctx;
}
```

---

### [LOW] LEAK-012 — Inconsistent Memory Function Usage in SM9
**File:** `crypto/sm9/src/sm9_sign.c`, `crypto/sm9/src/sm9_eal.c`

**Description:** SM9 code uses `malloc`/`free` instead of `BSL_SAL_Malloc`/`BSL_SAL_Free`, inconsistent with rest of codebase.

**Remediation:** Replace with BSL_SAL functions for consistency.

---

## Summary Table

| ID | File | Line | Severity | Description |
|----|------|------|----------|-------------|
| LEAK-001 | parse_extensions_server.c | 311-364 | HIGH | ParseIdentities leaks linked list on error |
| LEAK-002 | parse_extensions_server.c | 412-463 | HIGH | ParseKeyShare leaks linked list on error |
| LEAK-003 | parse_certificate.c | 141-175 | HIGH | ParseCerts leaks cert chain on error |
| LEAK-004 | cmvp_selftest_ecdh.c | 55-106 | HIGH | GetPkey leaks pkeyPrv when pkeyPub fails |
| LEAK-005 | hs_common.c | 474-532 | HIGH | CheckClientPsk leaks pskInfo on error |
| LEAK-006 | send_client_hello.c | 375-399 | MEDIUM | ConstructUserPsk leaks pskSession |
| LEAK-007 | hitls_x509_ext.c | 273-286 | MEDIUM | ParseGeneralName potential double-free |
| LEAK-008 | hitls_cms_signdata.c | 700-748 | MEDIUM | EncodeX509List may leak asnBuf |
| LEAK-009 | parse_extensions_server.c | 97-144 | MEDIUM | ParseClientSignatureAlgorithms leak |
| LEAK-010 | hs_kx.c | 700-740 | MEDIUM | HS_KX_PskCheck leaks pskInfo |
| LEAK-011 | sm9_sign.c | 36-41 | LOW | SM9_NewCtx NULL dereference |
| LEAK-012 | sm9_*.c | Multiple | LOW | Inconsistent malloc/free usage |

---

## Recommendations

1. **Use goto-cleanup pattern:** Functions with multiple allocations should use a unified cleanup pattern:
```c
int32_t function() {
    void *ptr1 = NULL;
    void *ptr2 = NULL;
    int32_t ret = HITLS_SUCCESS;
    
    ptr1 = BSL_SAL_Calloc(...);
    if (ptr1 == NULL) { ret = HITLS_MEMALLOC_FAIL; goto cleanup; }
    
    ptr2 = BSL_SAL_Calloc(...);
    if (ptr2 == NULL) { ret = HITLS_MEMALLOC_FAIL; goto cleanup; }
    
    // ... work ...
    
cleanup:
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(ptr1);
        BSL_SAL_FREE(ptr2);
    }
    return ret;
}
```

2. **Add cleanup functions for complex structures:** For linked lists and complex structures, create dedicated cleanup functions.

3. **Use static analysis tools:** Enable AddressSanitizer (ASan) during testing to catch memory leaks automatically.

4. **Consistent memory allocation:** Replace all `malloc`/`free` with `BSL_SAL_Malloc`/`BSL_SAL_Free`.

5. **Add NULL checks:** Always check return values of allocation functions before using the pointer.