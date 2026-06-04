/*
 * alloc-shim.h — minimal standalone replacement for AFL/AFLNet's alloc-inl.h
 *
 * opcua-lift only needs three allocator entry points from the original AFLNet
 * tree: ck_alloc / ck_realloc / ck_free.  In AFLNet these live in alloc-inl.h,
 * which in turn pulls in config.h, types.h and debug.h.  To make opcua-lift a
 * self-contained tool that builds with a plain `cc` (no AFLNet checkout, no
 * aflnet.o), we provide tiny libc-backed equivalents here.
 *
 * Semantics preserved for the way extract_response_codes_opcua() uses them:
 *   - ck_alloc(n)        : zero-initialised allocation (calloc), abort on OOM.
 *   - ck_realloc(p, n)   : grow/shrink, abort on OOM; n==0 frees and returns NULL.
 *   - ck_free(p)         : free (NULL-safe).
 *
 * These are the only behaviours the lifted function relies on.  We intentionally
 * do NOT reproduce AFL's red-zone/canary debugging machinery — it is irrelevant
 * to replaying a corpus entry against a live server.
 */

#ifndef OPCUA_LIFT_ALLOC_SHIM_H
#define OPCUA_LIFT_ALLOC_SHIM_H

#include <stdlib.h>

static inline void *ck_alloc(size_t size) {
    if (size == 0) return NULL;
    void *ret = calloc(1, size);   /* AFL's ck_alloc zero-initialises */
    if (!ret) abort();
    return ret;
}

static inline void *ck_realloc(void *orig, size_t size) {
    if (size == 0) { free(orig); return NULL; }
    void *ret = realloc(orig, size);
    if (!ret) abort();
    return ret;
}

static inline void ck_free(void *mem) {
    free(mem);
}

#endif /* OPCUA_LIFT_ALLOC_SHIM_H */
