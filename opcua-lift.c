/*
 * opcua-lift.c — OPC UA seed lifter for afl++/symcc corpus replay
 *
 * Takes a raw corpus file (ReadRequest body bytes from function-level fuzzing
 * of UA_decodeBinary) and replays it through a live OPC UA session:
 *   HEL -> ACK -> OPN -> CreateSession -> ActivateSession -> MSG(fuzz) -> response
 *
 * Usage: ./opcua-lift <corpus_file> <port> [node_id [host]]
 *   corpus_file   Path to raw byte file (afl++/symcc corpus entry)
 *   port          TCP port of the target OPC UA server
 *   node_id       Optional: decimal service NodeId (default: 631 = ReadRequest)
 *   host          Optional: server hostname or IP (default: 127.0.0.1)
 *
 * Exit codes:
 *   0  Session established and MSG sent; response codes printed to stderr
 *   1  Handshake failed at any step
 *   2  Usage error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ck_alloc/ck_free/ck_realloc — needed to correctly free memory returned by
 * extract_response_codes_opcua, which allocates via ck_realloc internally.
 * In the standalone build these are libc-backed shims (see alloc-shim.h),
 * NOT the full AFLNet alloc-inl.h. */
#include "alloc-shim.h"

/* Forward declaration - defined in opcua_state.c (lifted verbatim from
 * aflnet.c).  No aflnet.o link required. */
unsigned int* extract_response_codes_opcua(unsigned char* buf,
    unsigned int buf_size, unsigned int* state_count_ref);

/* -----------------------------------------------------------------------
 * Baseline handshake messages extracted from testcases/opcua_seed_1st.raw
 * These are verbatim bytes from a real open62541 v1.3.4 session.
 * Dynamic fields (channelId, tokenId, seqNum, reqId, authToken) are patched
 * at runtime before sending.
 * ----------------------------------------------------------------------- */

/* HEL: 56 bytes. All fields are static for localhost:4840. */
static const uint8_t BASE_HEL[56] = {
    0x48, 0x45, 0x4c, 0x46, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x40, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
    0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30,
};

/* OPN: 132 bytes. secureChannelId=0, SecurityPolicy=None, seqNum=1, reqId=1.
 * Sent as-is; server responds with its assigned channelId and tokenId. */
static const uint8_t BASE_OPN[132] = {
    0x4f, 0x50, 0x4e, 0x46, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x63, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x55, 0x41, 0x2f, 0x53, 0x65, 0x63, 0x75,
    0x72, 0x69, 0x74, 0x79, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x23, 0x4e, 0x6f, 0x6e, 0x65, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0xbe, 0x01, 0x00, 0x00, 0x7f, 0x48, 0xa2, 0xba, 0x0c, 0x78, 0xdc, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xc0, 0x27, 0x09, 0x00,
};

/* CreateSession: 176 bytes. NodeId 461 (0x01cd).
 * Patch offsets (from byte 0 of this array):
 *   [8..11]  channelId  (uint32 LE)
 *   [12..15] tokenId    (uint32 LE)
 *   [16..19] seqNum     (uint32 LE) -> set to 2
 *   [20..23] reqId      (uint32 LE) -> set to 2
 * authToken in RequestHeader is already null NodeId (bytes [28..29] = 00 00),
 * which is correct for CreateSession (no prior session token needed). */
static const uint8_t BASE_CREATESESSION[176] = {
    0x4d, 0x53, 0x47, 0x46, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0xcd, 0x01, 0x00, 0x00, 0xb1, 0x73,
    0xa2, 0xba, 0x0c, 0x78, 0xdc, 0x01, 0xa3, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x75, 0x72, 0x6e,
    0x3a, 0x6f, 0x70, 0x65, 0x6e, 0x36, 0x32, 0x35, 0x34, 0x31, 0x2e, 0x75, 0x6e, 0x63, 0x6f, 0x6e,
    0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x64, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x18, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x63, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
    0x6f, 0x73, 0x74, 0x3a, 0x34, 0x38, 0x34, 0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x80, 0x4f, 0x32, 0x41, 0xff, 0xff, 0xff, 0x7f,
};

/* ActivateSession TypeId bytes (NodeId 467, FourByte encoding) */
static const uint8_t ACTVSESS_TYPEID[4] = { 0x01, 0x00, 0xd3, 0x01 };

/*
 * UserNameIdentityToken ExtensionObject (63 bytes), SecurityPolicy=None.
 *
 * Lifted verbatim from a working open62541 AFLNet seed that reaches
 * ActivateSession against the server_ctt target (anonymous login disabled by
 * default via disableAnonymous(), so a null/anonymous token gets
 * Bad_IdentityTokenInvalid 0x80200000). Credentials user1/password with
 * policyId "open62541-username-policy" are the open62541 defaults the target
 * accepts. Password is plaintext because SecurityPolicy=None.
 *
 * Layout:
 *   01 00 44 01                TypeId NodeId i=324 (UserNameIdentityToken_Encoding_DefaultBinary)
 *   01                         encoding = has binary body
 *   36 00 00 00                bodyLen = 54
 *     19 00 00 00 "open62541-username-policy"   policyId (String, 25)
 *     05 00 00 00 "user1"                        userName (String, 5)
 *     08 00 00 00 "password"                     password (ByteString, 8, plaintext @ None)
 *     ff ff ff ff                                encryptionAlgorithm (null String)
 */
static const uint8_t USERNAME_IDENTITY_TOKEN[] = {
    0x01, 0x00, 0x44, 0x01, 0x01, 0x36, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x65, 0x6e, 0x36, 0x32, 0x35, 0x34, 0x31, 0x2d, 0x75, 0x73, 0x65,
    0x72, 0x6e, 0x61, 0x6d, 0x65, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x05,
    0x00, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x31, 0x08, 0x00, 0x00, 0x00, 0x70,
    0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xff, 0xff, 0xff, 0xff,
};

/*
 * AnonymousIdentityToken ExtensionObject (49 bytes) for open62541 v1.4.x.
 *
 * Captured verbatim from open62541 v1.4.6's own UA_Client connecting anonymously
 * to a clean (non-fuzzing) v1.4.6 server. v1.4 changed the default anonymous
 * policyId from "open62541-anonymous-policy" (v1.3.x) to
 * "open62541-anonymous-policy-none#None" (security-policy suffix appended). A
 * null/empty token or the short-form policyId is rejected with
 * Bad_IdentityTokenInvalid (0x80200000); the full suffixed policyId is required.
 *
 * NOTE: this only works against a CLEAN v1.4.6 build. afl-gcc auto-defines
 * FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, under which open62541 tampers with
 * auth tokens (ua_server.c) and ActivateSession fails regardless of token.
 *
 * Layout:
 *   01 00 41 01                TypeId NodeId i=321 (AnonymousIdentityToken_Encoding_DefaultBinary)
 *   01                         encoding = has binary body
 *   28 00 00 00                bodyLen = 40
 *     24 00 00 00 "open62541-anonymous-policy-none#None"   policyId (String, 36)
 */
static const uint8_t ANON_V14_IDENTITY_TOKEN[] = {
    0x01, 0x00, 0x41, 0x01, 0x01, 0x28, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0x6f, 0x70, 0x65, 0x6e, 0x36, 0x32, 0x35, 0x34, 0x31, 0x2d, 0x61, 0x6e, 0x6f,
    0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
    0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x23, 0x4e, 0x6f, 0x6e, 0x65,
};

/*
 * build_activate_session_body: construct an ActivateSession request body with
 * a UserName identity token (user1/password).
 *
 * The target (server_ctt) disables anonymous login by default, so a null/empty
 * UserIdentityToken is rejected with Bad_IdentityTokenInvalid. We send the same
 * UserName token that working AFLNet seeds use. If your target permits
 * anonymous login, swap USERNAME_IDENTITY_TOKEN for the 3-byte null ExtObj
 * (00 00 00) instead.
 *
 * Body layout (87 bytes):
 *   clientSignature.algorithm  (null String)    4 bytes  ff ff ff ff
 *   clientSignature.signature  (null ByteStr)   4 bytes  ff ff ff ff
 *   clientSoftwareCertificates (null Int32 arr) 4 bytes  ff ff ff ff
 *   localeIds                  (null Int32 arr) 4 bytes  ff ff ff ff
 *   userIdentityToken          (UserName ExtObj) 63 bytes
 *   userTokenSignature.algo    (null String)    4 bytes  ff ff ff ff
 *   userTokenSignature.sig     (null ByteStr)   4 bytes  ff ff ff ff
 */
static void build_activate_session_body(uint8_t *body, uint32_t *body_len) {
    uint32_t off = 0;
    /* clientSignature (null SignatureData = null String + null ByteString) */
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    /* clientSoftwareCertificates: null array */
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    /* localeIds: null array */
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    /* userIdentityToken: 環境変数で切り替え可能 (ベンダーごとの auth 差に対応):
     *   OPCUA_LIFT_ANON=1     → 匿名 (null ExtObj 3B)。anon 許可サーバ向け。
     *   OPCUA_LIFT_TOKEN_HEX  → 任意トークンを hex で指定 (working seed から抽出した値)。
     *   既定                  → UserName token (user1/password)。 */
    const char *anon = getenv("OPCUA_LIFT_ANON");
    const char *thex = getenv("OPCUA_LIFT_TOKEN_HEX");
    const char *anon14 = getenv("OPCUA_LIFT_ANON_V14");
    if (anon && anon[0] == '1') {
        body[off++]=0x00; body[off++]=0x00; body[off++]=0x00;  /* null ExtObj */
    } else if (anon14 && anon14[0] == '1') {
        /* open62541 v1.4.x clean build: anonymous with suffixed policyId */
        memcpy(body + off, ANON_V14_IDENTITY_TOKEN, sizeof(ANON_V14_IDENTITY_TOKEN));
        off += (uint32_t)sizeof(ANON_V14_IDENTITY_TOKEN);
    } else if (thex && thex[0]) {
        for (const char *p = thex; p[0] && p[1]; p += 2) {
            unsigned v; sscanf(p, "%2x", &v); body[off++] = (uint8_t)v;
        }
    } else {
        memcpy(body + off, USERNAME_IDENTITY_TOKEN, sizeof(USERNAME_IDENTITY_TOKEN));
        off += (uint32_t)sizeof(USERNAME_IDENTITY_TOKEN);
    }
    /* userTokenSignature (null SignatureData) */
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    body[off++]=0xff; body[off++]=0xff; body[off++]=0xff; body[off++]=0xff;
    *body_len = off;
}

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

static inline uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static inline void wr_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v>>8)&0xff;
    p[2] = (v>>16)&0xff; p[3] = (v>>24)&0xff;
}

/*
 * recv_opcua_msg: read exactly one OPC UA message from the socket.
 * Reads the 8-byte header, extracts msg_size from bytes 4-7 (LE uint32),
 * then reads the remaining msg_size-8 bytes.
 * Returns 0 on success (caller must free *buf_out), -1 on error.
 */
static int recv_opcua_msg(int sockfd, uint8_t **buf_out, uint32_t *size_out) {
    uint8_t hdr[8];
    ssize_t r;
    uint32_t got = 0;

    while (got < 8) {
        r = recv(sockfd, hdr + got, 8 - got, 0);
        if (r <= 0) return -1;
        got += (uint32_t)r;
    }

    uint32_t msg_size = rd_le32(hdr + 4);
    if (msg_size < 8 || msg_size > 4*1024*1024) return -1;

    uint8_t *buf = malloc(msg_size);
    if (!buf) return -1;
    memcpy(buf, hdr, 8);

    got = 8;
    while (got < msg_size) {
        r = recv(sockfd, buf + got, msg_size - got, 0);
        if (r <= 0) { free(buf); return -1; }
        got += (uint32_t)r;
    }

    *buf_out = buf;
    *size_out = msg_size;
    return 0;
}

/*
 * send_all: write exactly len bytes to sockfd, retrying on partial sends.
 */
static int send_all(int sockfd, const uint8_t *buf, uint32_t len) {
    uint32_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sockfd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        sent += (uint32_t)r;
    }
    return 0;
}

/*
 * nodeid_wire_len: return byte length of a binary-encoded NodeId starting at
 * buf[off].  Returns 0 if encoding byte is unrecognised or out of bounds.
 * Handles base encodings 0x00..0x05 (ExpandedNodeId flags in upper 2 bits
 * are masked out; namespace-URI and server-index extensions are not present
 * in normal in-band NodeIds returned by open62541).
 */
/* max wire length of an authToken NodeId (Milo opaque = 39B; margin for larger) */
#define AUTH_TOK_MAX 128

static uint32_t nodeid_wire_len(const uint8_t *buf, uint32_t len, uint32_t off) {
    if (off >= len) return 0;
    uint8_t enc = buf[off] & 0x3f;  /* lower 6 bits = base encoding */
    switch (enc) {
        case 0x00: return 2;   /* TwoByte:  enc(1) + id(1) */
        case 0x01: return 4;   /* FourByte: enc(1) + ns(1) + id(2) */
        case 0x02: return 7;   /* Numeric:  enc(1) + ns(2) + id(4) */
        case 0x03: {            /* String:   enc(1) + ns(2) + len(4) + data */
            if (off + 7 > len) return 0;
            int32_t slen = (int32_t)rd_le32(buf + off + 3);
            if (slen < 0) return 7;          /* null string */
            return 7 + (uint32_t)slen;
        }
        case 0x04: return 19;  /* GUID:     enc(1) + ns(2) + guid(16) */
        case 0x05: {            /* ByteString: enc(1) + ns(2) + len(4) + data */
            if (off + 7 > len) return 0;
            int32_t blen = (int32_t)rd_le32(buf + off + 3);
            if (blen < 0) return 7;
            return 7 + (uint32_t)blen;
        }
        default: return 0;
    }
}


/*
 * skip_diagnostic_info / skip_response_header
 *
 * ResponseHeader is VARIABLE length.  serviceDiagnostics (DiagnosticInfo),
 * stringTable (String[]) and additionalHeader (ExtensionObject) all grow.
 * Assuming a fixed 24 bytes works only for the minimal form that open62541
 * happens to send; any server returning diagnostics or a non-empty
 * stringTable shifts sessionId/authToken and the session then fails with a
 * decoding error that looks like a target bug.
 *
 * Returns the new offset, or 0 on failure (fail closed).
 */
static uint32_t skip_diagnostic_info(const uint8_t *buf, uint32_t len,
                                     uint32_t off, int depth) {
    if (depth > 8 || off >= len) return 0;
    uint8_t mask = buf[off++];
    if (mask & 0x80) return 0;                 /* reserved bit */
    /* bits 0..3 (SymbolicId, NamespaceUri, LocalizedText, Locale) are Int32.
     * They are all 4 bytes, so their relative wire order does not matter here. */
    for (int b = 0; b < 4; b++) {
        if (mask & (1u << b)) { if (off + 4 > len) return 0; off += 4; }
    }
    if (mask & 0x10) {                          /* AdditionalInfo (String) */
        if (off + 4 > len) return 0;
        int32_t n = (int32_t)rd_le32(buf + off); off += 4;
        if (n > 0) { if (off + (uint32_t)n > len) return 0; off += (uint32_t)n; }
    }
    if (mask & 0x20) { if (off + 4 > len) return 0; off += 4; }  /* InnerStatusCode */
    if (mask & 0x40) {                          /* InnerDiagnosticInfo (recursive) */
        off = skip_diagnostic_info(buf, len, off, depth + 1);
        if (off == 0) return 0;
    }
    return off;
}

static uint32_t skip_response_header(const uint8_t *buf, uint32_t len,
                                     uint32_t off, uint32_t *service_result) {
    if (off + 16 > len) return 0;
    off += 8;                                   /* timestamp   */
    off += 4;                                   /* requestHandle */
    if (service_result) *service_result = rd_le32(buf + off);
    off += 4;                                   /* serviceResult */

    off = skip_diagnostic_info(buf, len, off, 0);
    if (off == 0) return 0;

    /* stringTable (String[]) */
    if (off + 4 > len) return 0;
    int32_t nstr = (int32_t)rd_le32(buf + off); off += 4;
    if (nstr > 0) {
        for (int32_t i = 0; i < nstr; i++) {
            if (off + 4 > len) return 0;
            int32_t sl = (int32_t)rd_le32(buf + off); off += 4;
            if (sl > 0) { if (off + (uint32_t)sl > len) return 0; off += (uint32_t)sl; }
        }
    }

    /* additionalHeader (ExtensionObject: NodeId + encoding + optional body) */
    uint32_t nl = nodeid_wire_len(buf, len, off);
    if (nl == 0) return 0;
    off += nl;
    if (off >= len) return 0;
    uint8_t enc = buf[off++];
    if (enc == 0x01 || enc == 0x02) {
        if (off + 4 > len) return 0;
        int32_t bl = (int32_t)rd_le32(buf + off); off += 4;
        if (bl > 0) { if (off + (uint32_t)bl > len) return 0; off += (uint32_t)bl; }
    } else if (enc != 0x00) {
        return 0;                               /* undefined encoding */
    }
    return off;
}

/*
 * parse_opn_response: extract channelId (bytes 8-11) and tokenId from the
 * OPN response by walking the variable-length AsymmetricSecurityHeader.
 */
static int parse_opn_response(const uint8_t *buf, uint32_t len,
                               uint32_t *channel_id, uint32_t *token_id) {
    if (len < 12) return -1;
    *channel_id = rd_le32(buf + 8);

    uint32_t off = 12;

    /* AsymmetricSecurityHeader */
    /* PolicyUri (String: int32 len + bytes) */
    if (off + 4 > len) return -1;
    int32_t uri_len = (int32_t)rd_le32(buf + off); off += 4;
    if (uri_len > 0) {
        if (off + (uint32_t)uri_len > len) return -1;
        off += (uint32_t)uri_len;
    }
    /* SenderCertificate (ByteString) */
    if (off + 4 > len) return -1;
    int32_t cert_len = (int32_t)rd_le32(buf + off); off += 4;
    if (cert_len > 0) {
        if (off + (uint32_t)cert_len > len) return -1;
        off += (uint32_t)cert_len;
    }
    /* ReceiverCertThumbprint (ByteString) */
    if (off + 4 > len) return -1;
    int32_t thumb_len = (int32_t)rd_le32(buf + off); off += 4;
    if (thumb_len > 0) {
        if (off + (uint32_t)thumb_len > len) return -1;
        off += (uint32_t)thumb_len;
    }

    /* SequenceHeader: seqNum(4) + reqId(4) */
    if (off + 8 > len) return -1;
    off += 8;

    /* TypeId (NodeId for OpenSecureChannelResponse) */
    uint32_t nlen = nodeid_wire_len(buf, len, off);
    if (nlen == 0) return -1;
    off += nlen;

    /* ResponseHeader (VARIABLE length - see skip_response_header) */
    off = skip_response_header(buf, len, off, NULL);
    if (off == 0) return -1;

    /* serverProtocolVersion (UInt32) */
    if (off + 4 > len) return -1;
    off += 4;

    /* ChannelSecurityToken.channelId (UInt32) - skip */
    if (off + 4 > len) return -1;
    off += 4;

    /* ChannelSecurityToken.tokenId */
    if (off + 4 > len) return -1;
    *token_id = rd_le32(buf + off);
    return 0;
}

/*
 * parse_create_session_resp: extract the authToken NodeId from a
 * CreateSession response.
 *
 * Layout after 24-byte transport header:
 *   TypeId (NodeId, 4 bytes for enc=0x01)
 *   ResponseHeader (variable length; walked by skip_response_header)
 *   sessionId (NodeId, variable)
 *   authToken (NodeId, variable) <- we want this
 *
 * Returns 0 on success; -1 on parse error; -2 on bad StatusCode.
 * auth_tok must be at least AUTH_TOK_MAX bytes.  Servers differ widely here:
 * open62541 issues a short numeric NodeId, while Eclipse Milo issues an opaque
 * (ByteString) NodeId carrying 32 random bytes = 39 bytes on the wire.  Both are
 * spec-conformant, so the buffer must accommodate the larger opaque form.
 */
static int parse_create_session_resp(const uint8_t *buf, uint32_t len,
                                      uint8_t *auth_tok, uint32_t *auth_tok_len) {
    if (len < 24) return -1;
    uint32_t off = 24;  /* skip MSG transport header */

    /* TypeId */
    uint32_t nlen = nodeid_wire_len(buf, len, off);
    if (nlen == 0) return -1;
    off += nlen;

    /* ResponseHeader (VARIABLE length - see skip_response_header) */
    uint32_t status = 0;
    off = skip_response_header(buf, len, off, &status);
    if (off == 0) return -1;
    if (status != 0) return -2;

    /* sessionId (NodeId) - skip */
    nlen = nodeid_wire_len(buf, len, off);
    if (nlen == 0) return -1;
    off += nlen;

    /* authToken (NodeId) */
    nlen = nodeid_wire_len(buf, len, off);
    if (nlen == 0 || nlen > AUTH_TOK_MAX) return -1;
    if (off + nlen > len) return -1;  /* bounds check before memcpy */
    *auth_tok_len = nlen;
    memcpy(auth_tok, buf + off, nlen);
    return 0;
}

/*
 * build_msg: construct a complete OPC UA MSG frame.
 * Returns a malloc'd buffer of *out_len bytes, or NULL on OOM.
 *
 * Layout: MSGF(4) + total_size(4) + channelId(4) + tokenId(4) +
 *         seqNum(4) + reqId(4) +
 *         nodeid(nodeid_len) +
 *         reqhdr(reqhdr_len) +
 *         body(body_len)
 */
static uint8_t *build_msg(uint32_t channel_id, uint32_t token_id,
                           uint32_t seq_num, uint32_t req_id,
                           const uint8_t *nodeid, uint32_t nodeid_len,
                           const uint8_t *reqhdr, uint32_t reqhdr_len,
                           const uint8_t *body, uint32_t body_len,
                           uint32_t *out_len) {
    uint32_t total = 24 + nodeid_len + reqhdr_len + body_len;
    uint8_t *buf = malloc(total);
    if (!buf) return NULL;

    buf[0] = 'M'; buf[1] = 'S'; buf[2] = 'G'; buf[3] = 'F';
    wr_le32(buf + 4, total);
    wr_le32(buf + 8, channel_id);
    wr_le32(buf + 12, token_id);
    wr_le32(buf + 16, seq_num);
    wr_le32(buf + 20, req_id);

    uint32_t off = 24;
    memcpy(buf + off, nodeid, nodeid_len); off += nodeid_len;
    memcpy(buf + off, reqhdr, reqhdr_len); off += reqhdr_len;
    if (body_len > 0) memcpy(buf + off, body, body_len);

    *out_len = total;
    return buf;
}

/*
 * build_request_header: construct a minimal OPC UA RequestHeader.
 * auth_tok is the live authToken NodeId (variable length).
 * Returns malloc'd bytes; caller must free.
 */
static uint8_t *build_request_header(const uint8_t *auth_tok, uint32_t auth_tok_len,
                                      uint32_t req_handle, uint32_t *out_len) {
    /* authToken + timestamp(8) + requestHandle(4) + returnDiagnostics(4)
     * + auditEntryId(4=-1) + timeoutHint(4) + additionalHeader(3) */
    uint32_t total = auth_tok_len + 8 + 4 + 4 + 4 + 4 + 3;
    uint8_t *h = calloc(1, total);
    if (!h) return NULL;

    uint32_t off = 0;
    memcpy(h + off, auth_tok, auth_tok_len); off += auth_tok_len;

    /* UA_DateTime: 100ns intervals since Jan 1, 1601.
     * Offset from Unix epoch (Jan 1 1970) to OPC UA epoch (Jan 1 1601):
     * 11644473600 seconds * 10^7 = 116444736000000000 ticks */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ua_time = (uint64_t)ts.tv_sec * 10000000ULL
                     + (uint64_t)ts.tv_nsec / 100ULL
                     + 116444736000000000ULL;
    h[off+0] = ua_time & 0xff;
    h[off+1] = (ua_time>>8)  & 0xff;
    h[off+2] = (ua_time>>16) & 0xff;
    h[off+3] = (ua_time>>24) & 0xff;
    h[off+4] = (ua_time>>32) & 0xff;
    h[off+5] = (ua_time>>40) & 0xff;
    h[off+6] = (ua_time>>48) & 0xff;
    h[off+7] = (ua_time>>56) & 0xff;
    off += 8;

    wr_le32(h + off, req_handle); off += 4;  /* requestHandle */
    wr_le32(h + off, 0);          off += 4;  /* returnDiagnostics = 0 */
    wr_le32(h + off, (uint32_t)-1); off += 4; /* auditEntryId = null string */
    wr_le32(h + off, 5000);       off += 4;  /* timeoutHint = 5000ms */
    /* additionalHeader: null ExtensionObject = NodeId(00 00) + encoding(00) */
    h[off] = 0x00; h[off+1] = 0x00; h[off+2] = 0x00;

    *out_len = total;
    return h;
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <corpus_file> <port> [node_id [host]]\n", argv[0]);
        return 2;
    }

    const char *corpus_file = argv[1];
    int port = atoi(argv[2]);
    uint32_t node_id = (argc >= 4) ? (uint32_t)atoi(argv[3]) : 631;
    const char *host = (argc >= 5) ? argv[4] : "127.0.0.1";

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "[opcua-lift] Usage error: invalid port %d\n", port);
        return 2;
    }

    /* --- Load corpus file --- */
    FILE *fp = fopen(corpus_file, "rb");
    if (!fp) {
        fprintf(stderr, "[opcua-lift] Cannot open corpus file: %s\n", strerror(errno));
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 0) {
        fprintf(stderr, "[opcua-lift] Cannot determine corpus file size: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    }
    rewind(fp);

    uint8_t *fuzz_body = NULL;
    uint32_t fuzz_len = 0;
    if (fsize > 0) {
        fuzz_body = malloc((size_t)fsize);
        if (!fuzz_body) { fclose(fp); return 1; }
        fuzz_len = (uint32_t)fread(fuzz_body, 1, (size_t)fsize, fp);
    }
    fclose(fp);

    /* --- Connect --- */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "[opcua-lift] Connect failed: cannot resolve %s\n", host);
        free(fuzz_body);
        return 1;
    }
    int sockfd = socket(res->ai_family, res->ai_socktype, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[opcua-lift] Connect failed: %s\n", strerror(errno));
        freeaddrinfo(res);
        free(fuzz_body);
        return 1;
    }
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "[opcua-lift] Connect failed: %s\n", strerror(errno));
        close(sockfd);
        freeaddrinfo(res);
        free(fuzz_body);
        return 1;
    }
    freeaddrinfo(res);

    /* Recv timeout (default 5s, avoids hanging under ASAN overhead).  Overridable
     * via OPCUA_LIFT_TIMEOUT (seconds): JVM-backed servers such as Eclipse Milo can
     * be slow to answer HEL when sessions are opened in rapid succession, and a
     * short timeout shows up as a spurious "HEL/ACK failed: no response".
     * This only changes how long the client waits — never what the server sends. */
    long timeout_s = 5;
    { const char *t = getenv("OPCUA_LIFT_TIMEOUT");
      if (t && *t) { long v = strtol(t, NULL, 10); if (v > 0 && v <= 300) timeout_s = v; } }
    struct timeval tv = {timeout_s, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int rc = 1;  /* assume failure until MSG send succeeds */
    uint8_t *resp = NULL;
    uint32_t resp_len = 0;
    uint8_t auth_tok[AUTH_TOK_MAX];
    uint32_t auth_tok_len = 0;
    uint32_t channel_id = 0, token_id = 0;

    /* ---- Step 1: HEL ---- */
    if (send_all(sockfd, BASE_HEL, sizeof(BASE_HEL)) < 0) {
        fprintf(stderr, "[opcua-lift] HEL/ACK failed: send error\n");
        goto done;
    }
    if (recv_opcua_msg(sockfd, &resp, &resp_len) < 0) {
        fprintf(stderr, "[opcua-lift] HEL/ACK failed: no response\n");
        goto done;
    }
    if (resp_len < 3 || memcmp(resp, "ACK", 3) != 0) {
        fprintf(stderr, "[opcua-lift] HEL/ACK failed: unexpected response type\n");
        free(resp);
        goto done;
    }
    free(resp); resp = NULL;

    /* ---- Step 2: OPN ---- */
    if (send_all(sockfd, BASE_OPN, sizeof(BASE_OPN)) < 0) {
        fprintf(stderr, "[opcua-lift] OPN failed: send error\n");
        goto done;
    }
    if (recv_opcua_msg(sockfd, &resp, &resp_len) < 0) {
        fprintf(stderr, "[opcua-lift] OPN failed: no response\n");
        goto done;
    }
    if (resp_len >= 3 && memcmp(resp, "ERR", 3) == 0) {
        uint32_t status = (resp_len >= 12) ? rd_le32(resp + 8) : 0;
        fprintf(stderr, "[opcua-lift] OPN failed: server returned ERR 0x%08x\n", status);
        free(resp);
        goto done;
    }
    if (parse_opn_response(resp, resp_len, &channel_id, &token_id) < 0) {
        fprintf(stderr, "[opcua-lift] OPN parse failed: malformed response\n");
        free(resp);
        goto done;
    }
    free(resp); resp = NULL;

    /* ---- Step 3: CreateSession ---- */
    {
        uint8_t cs[sizeof(BASE_CREATESESSION)];
        memcpy(cs, BASE_CREATESESSION, sizeof(cs));
        wr_le32(cs + 8,  channel_id);
        wr_le32(cs + 12, token_id);
        wr_le32(cs + 16, 2);  /* seqNum */
        wr_le32(cs + 20, 2);  /* reqId */

        if (send_all(sockfd, cs, sizeof(cs)) < 0) {
            fprintf(stderr, "[opcua-lift] CreateSession failed: send error\n");
            goto done;
        }
    }
    if (recv_opcua_msg(sockfd, &resp, &resp_len) < 0) {
        fprintf(stderr, "[opcua-lift] CreateSession failed: no response\n");
        goto done;
    }
    {
        int pr = parse_create_session_resp(resp, resp_len, auth_tok, &auth_tok_len);
        if (pr == -2) {
            uint32_t status = (resp_len >= 40) ? rd_le32(resp + 36) : 0;
            fprintf(stderr, "[opcua-lift] CreateSession failed: bad StatusCode 0x%08x\n", status);
            free(resp);
            goto done;
        }
        if (pr < 0) {
            fprintf(stderr, "[opcua-lift] CreateSession parse failed: malformed response\n");
            free(resp);
            goto done;
        }
    }
    free(resp); resp = NULL;

    /* ---- Step 4: ActivateSession ---- */
    {
        /* Build RequestHeader with live authToken */
        uint32_t rh_len;
        uint8_t *rh = build_request_header(auth_tok, auth_tok_len, 3, &rh_len);
        if (!rh) { fprintf(stderr, "[opcua-lift] OOM\n"); goto done; }

        /* Build body: UserName identity token (user1/password). 87 bytes. */
        uint8_t as_body[128];
        uint32_t as_body_len;
        build_activate_session_body(as_body, &as_body_len);

        uint32_t as_msg_len;
        uint8_t *as_msg = build_msg(channel_id, token_id, 3, 3,
                                     ACTVSESS_TYPEID, 4,
                                     rh, rh_len,
                                     as_body, as_body_len,
                                     &as_msg_len);
        free(rh);
        if (!as_msg) { fprintf(stderr, "[opcua-lift] OOM\n"); goto done; }
        int sr = send_all(sockfd, as_msg, as_msg_len);
        free(as_msg);
        if (sr < 0) {
            fprintf(stderr, "[opcua-lift] ActivateSession failed: send error\n");
            goto done;
        }
    }
    if (recv_opcua_msg(sockfd, &resp, &resp_len) < 0) {
        fprintf(stderr, "[opcua-lift] ActivateSession failed: no response\n");
        goto done;
    }
    {
        /* Check serviceResult in ActivateSession response.
         * Layout: transport(24) + TypeId(4) + ResponseHeader.
         * serviceResult is at transport(24) + TypeId(4) + timestamp(8) + handle(4) = offset 40 */
        if (resp_len >= 44) {
            uint32_t typeid_len = nodeid_wire_len(resp, resp_len, 24);
            if (typeid_len > 0 && 24 + typeid_len + 12 + 4 <= resp_len) {
                uint32_t status = rd_le32(resp + 24 + typeid_len + 12);
                if (status != 0) {
                    fprintf(stderr, "[opcua-lift] ActivateSession failed: bad StatusCode 0x%08x\n", status);
                    free(resp);
                    goto done;
                }
            }
        }
    }
    free(resp); resp = NULL;

    /* ---- Step 5: Send fuzz MSG ---- */
    {
        /* NodeId encoding: two-byte numeric (enc=0x01) for IDs <= 65535 */
        uint8_t nodeid_bytes[4];
        nodeid_bytes[0] = 0x01;  /* FourByte numeric NodeId */
        nodeid_bytes[1] = 0x00;  /* namespace = 0 */
        nodeid_bytes[2] = node_id & 0xff;
        nodeid_bytes[3] = (node_id >> 8) & 0xff;

        uint32_t rh_len;
        uint8_t *rh = build_request_header(auth_tok, auth_tok_len, 4, &rh_len);
        if (!rh) { fprintf(stderr, "[opcua-lift] OOM\n"); goto done; }

        uint32_t msg_len;
        uint8_t *msg = build_msg(channel_id, token_id, 4, 4,
                                  nodeid_bytes, 4,
                                  rh, rh_len,
                                  fuzz_body, fuzz_len,
                                  &msg_len);
        free(rh);
        if (!msg) { fprintf(stderr, "[opcua-lift] OOM\n"); goto done; }
        int sr = send_all(sockfd, msg, msg_len);
        free(msg);
        if (sr < 0) {
            fprintf(stderr, "[opcua-lift] MSG send failed\n");
            goto done;
        }
    }

    /* ---- Step 6: Collect response and print state codes ---- */
    {
        /* Drain response with poll-like timeout semantics: try recv_opcua_msg
         * (SO_RCVTIMEO already set to 5s above).  Collect all bytes received. */
        uint8_t *response_buf = NULL;
        uint32_t response_buf_size = 0;

        uint8_t *chunk = NULL;
        uint32_t chunk_len = 0;
        while (recv_opcua_msg(sockfd, &chunk, &chunk_len) == 0) {
            uint8_t *tmp = realloc(response_buf, response_buf_size + chunk_len);
            if (!tmp) { free(chunk); break; }
            response_buf = tmp;
            memcpy(response_buf + response_buf_size, chunk, chunk_len);
            response_buf_size += chunk_len;
            free(chunk); chunk = NULL;
            /* Only one MSG response expected; stop after first complete message */
            break;
        }

        if (response_buf && response_buf_size > 0) {
            unsigned int state_count = 0;
            unsigned int *codes = extract_response_codes_opcua(
                (unsigned char *)response_buf, response_buf_size, &state_count);
            if (codes) {
                for (unsigned int i = 0; i < state_count; i++)
                    fprintf(stderr, "%u-", codes[i]);
                fprintf(stderr, "\n");
                ck_free(codes);
            }
            /* Raw response bytes → STDOUT (binary-clean, so callers can capture
             * the MSG response without parsing it out of stderr diagnostics).
             * state codes stay on stderr. */
            fwrite(response_buf, 1, response_buf_size, stdout);
            fflush(stdout);
            free(response_buf);
        }
    }

    /* ---- Step 7: CloseSession (clean teardown) ----
     * opcua-lift は本来セッションを張りっぱなしで切断していたため、エージェントが
     * 毎サイクル数十回 replay するとサーバ側にセッションが溜まり Bad_TooManySessions
     * (0x80560000) で CreateSession が失敗するようになっていた。明示的に CloseSession
     * を送ってセッションを解放する。応答は待たない (teardown なので best-effort)。
     * CloseSession Request TypeId = NodeId 473 (0x01D9, FourByte)。
     * body = deleteSubscriptions (Boolean, 1B)。 */
    {
        static const uint8_t CLOSESESS_TYPEID[4] = { 0x01, 0x00, 0xd9, 0x01 };
        uint32_t rh_len;
        uint8_t *rh = build_request_header(auth_tok, auth_tok_len, 5, &rh_len);
        if (rh) {
            uint8_t cs_body[1] = { 0x01 };  /* deleteSubscriptions = true */
            uint32_t cs_len;
            uint8_t *cs = build_msg(channel_id, token_id, 5, 5,
                                    CLOSESESS_TYPEID, 4, rh, rh_len,
                                    cs_body, 1, &cs_len);
            free(rh);
            if (cs) { (void)send_all(sockfd, cs, cs_len); free(cs); }
        }
    }

    rc = 0;  /* success */

done:
    close(sockfd);
    free(fuzz_body);
    return rc;
}
