/*
 * test_response_header.c — ResponseHeader が可変長であることの回帰テスト。
 *
 * 従来 parse_create_session_resp() と parse_opn_response() は ResponseHeader を
 * **固定 24 byte** と仮定していた。open62541 が最小形（ちょうど 24 byte）を返すので
 * 実サーバ相手では露見しないが、diagnostics や stringTable を返すサーバでは
 * sessionId / authToken がずれ、以後の要求が復号エラーになる。
 * その失敗は「対象のバグ」に見えるので、静かに測定を壊す。
 *
 * static 関数を試すため実装をそのまま取り込む。
 *
 *   cc -O2 -o test_response_header test_response_header.c opcua_state.c && ./test_response_header
 */
#define main opcua_lift_main_unused
#include "opcua-lift.c"
#undef main

#include <assert.h>
#include <string.h>

static uint32_t put_u32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
    return 4;
}

/* 期待する authToken: Guid NodeId (ns=1) — open62541 が実際に返す形 */
static const uint8_t EXPECTED_TOKEN[19] = {
    0x04, 0x01, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

/*
 * CreateSessionResponse を組み立てる。
 *   diag_mask   0x00 なら診断なし。bit を立てると場が増える
 *   n_strings   stringTable の要素数（-1 で null）
 */
static uint32_t build_create_session_resp(uint8_t *b, uint8_t diag_mask,
                                          int32_t n_strings) {
    uint32_t o = 0;
    memset(b, 0, 24); o = 24;                       /* MSG transport header */

    b[o++] = 0x01; b[o++] = 0x00;                   /* TypeId: FourByte ns0 */
    o += put_u32(b + o, 464) - 2;                   /* i=464 は UInt16 なので 2 byte */
    b[o - 2] = 464 & 0xff; b[o - 1] = (464 >> 8) & 0xff;

    memset(b + o, 0, 8); o += 8;                    /* timestamp */
    o += put_u32(b + o, 1);                         /* requestHandle */
    o += put_u32(b + o, 0);                         /* serviceResult = Good */

    b[o++] = diag_mask;                             /* serviceDiagnostics */
    if (diag_mask & 0x01) o += put_u32(b + o, 7);   /* SymbolicId */
    if (diag_mask & 0x10) {                         /* AdditionalInfo */
        o += put_u32(b + o, 5);
        memcpy(b + o, "hello", 5); o += 5;
    }
    if (diag_mask & 0x20) o += put_u32(b + o, 0x80340000);  /* InnerStatusCode */

    o += put_u32(b + o, (uint32_t)n_strings);       /* stringTable */
    for (int32_t i = 0; i < n_strings; i++) {
        o += put_u32(b + o, 3);
        memcpy(b + o, "abc", 3); o += 3;
    }

    b[o++] = 0x00; b[o++] = 0x00; b[o++] = 0x00;    /* additionalHeader: null ExtObj */

    b[o++] = 0x01; b[o++] = 0x01;                   /* sessionId: FourByte ns1 */
    b[o++] = 0x92; b[o++] = 0x10;                   /* i=4242 */

    memcpy(b + o, EXPECTED_TOKEN, sizeof EXPECTED_TOKEN);
    o += sizeof EXPECTED_TOKEN;
    return o;
}

static int failures = 0;

static void check_token(const char *what, uint8_t diag, int32_t nstr) {
    uint8_t buf[512];
    uint8_t tok[AUTH_TOK_MAX];
    uint32_t tok_len = 0;
    uint32_t len = build_create_session_resp(buf, diag, nstr);

    int rc = parse_create_session_resp(buf, len, tok, &tok_len);
    if (rc != 0) {
        printf("FAIL %-34s parse rc=%d\n", what, rc);
        failures++;
        return;
    }
    if (tok_len != sizeof EXPECTED_TOKEN ||
        memcmp(tok, EXPECTED_TOKEN, sizeof EXPECTED_TOKEN) != 0) {
        printf("FAIL %-34s authToken がずれた (len=%u)\n", what, tok_len);
        failures++;
        return;
    }
    printf("PASS %-34s authToken を正しく取得\n", what);
}

int main(void) {
    /* 最小形。従来コードもここは通る（open62541 が返すのはこれ） */
    check_token("最小 ResponseHeader (24 byte)", 0x00, -1);

    /* **従来コードが壊れる形** */
    check_token("stringTable 1 件", 0x00, 1);
    check_token("stringTable 3 件", 0x00, 3);
    check_token("diagnostics (SymbolicId)", 0x01, -1);
    check_token("diagnostics (AdditionalInfo)", 0x10, -1);
    check_token("diagnostics + stringTable 2 件", 0x11, 2);
    check_token("InnerStatusCode つき診断", 0x20, -1);

    /* 切り詰めは fail closed であること */
    {
        uint8_t buf[512], tok[AUTH_TOK_MAX];
        uint32_t tok_len = 0;
        uint32_t len = build_create_session_resp(buf, 0x11, 2);
        int bad = 0;
        for (uint32_t n = 24; n < len; n++) {
            if (parse_create_session_resp(buf, n, tok, &tok_len) == 0) { bad = 1; break; }
        }
        if (bad) { printf("FAIL 切り詰めを受理した\n"); failures++; }
        else printf("PASS %-34s 切り詰めは fail closed\n", "truncation");
    }

    /* --- script parsing ------------------------------------------------
     * v1 scripts must keep parsing unchanged, and a v2 script must reject any
     * patch it cannot apply safely. A patch that reads from a response that
     * does not exist yet, or that writes past the end of the body it targets,
     * is a malformed script -- accepting it would mean sending a request built
     * from whatever happened to be in memory. */
    {
        lift_service_t *svcs = NULL;
        uint32_t n = 0;

        /* v1: {node_id=631, body_len=2, body} -- no header, no patch count */
        uint8_t v1[] = { 0x77,0x02,0,0,  2,0,0,0,  0xAA,0xBB };
        if (parse_script(v1, sizeof(v1), &svcs, &n) == 0 && n == 1 &&
            svcs[0].node_id == 631 && svcs[0].body_len == 2 && svcs[0].n_patches == 0) {
            printf("PASS %-34s v1 は従来どおり\n", "script v1 (no header)");
        } else { printf("FAIL v1 script\n"); failures++; }
        free_services(svcs, n); svcs = NULL; n = 0;

        /* v2 with one in-range patch */
        uint8_t v2[] = { 'L','F','T','S', 2,0,0,0,
                         0x0F,0x02,0,0, 4,0,0,0, 1,2,3,4, 0,0,0,0,          /* svc0, 0 patches */
                         0x15,0x02,0,0, 8,0,0,0, 1,2,3,4,5,6,7,8, 1,0,0,0, /* svc1, 1 patch  */
                         0,0,0,0,  12,0,0,0,  4,0,0,0,  4,0,0,0 };
        if (parse_script(v2, sizeof(v2), &svcs, &n) == 0 && n == 2 &&
            svcs[1].n_patches == 1 && svcs[1].patches[0].src_index == 0 &&
            svcs[1].patches[0].src_off == 12 && svcs[1].patches[0].dst_off == 4 &&
            svcs[1].patches[0].len == 4) {
            printf("PASS %-34s patch が読める\n", "script v2");
        } else { printf("FAIL v2 script\n"); failures++; }
        free_services(svcs, n); svcs = NULL; n = 0;

        /* src_index points at this very request: no response exists yet */
        uint8_t fwd[] = { 'L','F','T','S', 2,0,0,0,
                          0x15,0x02,0,0, 8,0,0,0, 1,2,3,4,5,6,7,8, 1,0,0,0,
                          0,0,0,0,  0,0,0,0,  0,0,0,0,  4,0,0,0 };
        if (parse_script(fwd, sizeof(fwd), &svcs, &n) < 0) {
            printf("PASS %-34s 自分自身の応答は参照不可\n", "patch src_index >= self");
        } else { printf("FAIL forward reference accepted\n"); failures++; free_services(svcs, n); }
        svcs = NULL; n = 0;

        /* dst_off + len runs past the end of an 8-byte body */
        uint8_t ovf[] = { 'L','F','T','S', 2,0,0,0,
                          0x0F,0x02,0,0, 4,0,0,0, 1,2,3,4, 0,0,0,0,
                          0x15,0x02,0,0, 8,0,0,0, 1,2,3,4,5,6,7,8, 1,0,0,0,
                          0,0,0,0,  0,0,0,0,  6,0,0,0,  4,0,0,0 };
        if (parse_script(ovf, sizeof(ovf), &svcs, &n) < 0) {
            printf("PASS %-34s body 外への書き込みを拒否\n", "patch dst overflow");
        } else { printf("FAIL out-of-range dst accepted\n"); failures++; free_services(svcs, n); }
        svcs = NULL; n = 0;

        /* An unknown version must not be parsed as if it were understood */
        uint8_t ver[] = { 'L','F','T','S', 99,0,0,0 };
        if (parse_script(ver, sizeof(ver), &svcs, &n) < 0) {
            printf("PASS %-34s 未知バージョンを拒否\n", "script version guard");
        } else { printf("FAIL unknown version accepted\n"); failures++; free_services(svcs, n); }
    }

    printf("\n%s\n", failures ? "FAILURES" : "all passed");
    return failures ? 1 : 0;
}
