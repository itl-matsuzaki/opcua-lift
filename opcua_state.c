/*
 * opcua_state.c — OPC UA response-code (state) extractor
 *
 * This is a verbatim lift of extract_response_codes_opcua() from AFLNet's
 * aflnet.c (the OPCUA protocol support added in the AFLNet extension PR).
 * It is the ONLY symbol opcua-lift needs from the AFLNet tree, so we carry
 * just this one function here instead of linking the whole 2900-line aflnet.o.
 *
 * Behaviour: walks a buffer of concatenated OPC UA messages, and for each
 * message emits a "state" code:
 *   - 0x00 for a normal (non-ERR) message
 *   - for an ERR message, the byte at offset 10 of that message (the low byte
 *     of the 32-bit error StatusCode), used by AFLNet as a coarse state id.
 * The returned array is allocated with ck_realloc(); the caller frees it with
 * ck_free().  *state_count_ref receives the number of codes (>=1; index 0 is a
 * fixed initial state 0).
 *
 * Source of truth: aflnet.c @ 212b578 (AFLNet OPCUA extension).  If the upstream
 * function changes, re-lift it here to stay byte-compatible with aflnet-replay.
 */

#include "alloc-shim.h"   /* ck_alloc / ck_realloc / ck_free */

unsigned int* extract_response_codes_opcua(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref)
{
    unsigned int byte_pos = 0;
    unsigned int mem_pos = 0;
    unsigned int mem_capacity = 1024;
    unsigned char msg_type;
    unsigned int* state_codes = NULL;
    unsigned int state_count = 0;
    char *temp_mem;

    temp_mem = (char *)ck_alloc(mem_capacity);

    // Initialize with a default state
    state_codes = (unsigned int *)ck_realloc(state_codes, sizeof(unsigned int));
    state_codes[state_count++] = 0;

    while (byte_pos < buf_size) {
        temp_mem[mem_pos++] = buf[byte_pos++];

        if (mem_pos >= 8) {
            if (temp_mem[0] == 'E' && temp_mem[1] == 'R' && temp_mem[2] == 'R') {
                /* ERR error code is at bytes 8-11 of the message.
                 * temp_mem only has 8 bytes accumulated; read from buf directly. */
                unsigned int msg_start = byte_pos - 8;
                msg_type = (msg_start + 10 < buf_size) ? buf[msg_start + 10] : 0;
            } else {
                msg_type = 0x00;
            }

            unsigned int msg_size = ((unsigned int)temp_mem[4]) |
                                    ((unsigned int)temp_mem[5] << 8) |
                                    ((unsigned int)temp_mem[6] << 16) |
                                    ((unsigned int)temp_mem[7] << 24);

            unsigned int bytes_to_skip = msg_size - 8;
            unsigned int skip_count = 0;
            while (byte_pos < buf_size && skip_count < bytes_to_skip) {
                byte_pos++;
                skip_count++;
            }

            state_codes = (unsigned int *)ck_realloc(state_codes, (state_count + 1) * sizeof(unsigned int));
            state_codes[state_count++] = (unsigned int)msg_type;
            mem_pos = 0;
        }

        if (mem_pos == mem_capacity) {
            mem_capacity *= 2;
            temp_mem = (char *)ck_realloc(temp_mem, mem_capacity);
        }
    }

    if (temp_mem) {
        ck_free(temp_mem);
    }

    *state_count_ref = state_count;
    return state_codes;
}
