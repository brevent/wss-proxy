#include <string.h>
#include <arpa/inet.h>
#include "ws-header.h"

/**
 * fop: fin:1, rsv:3, opcode: 4
 * mlen: mask: 1, length: 7
 */
#define FOP_MASK struct {   \
    uint8_t fop;            \
    uint8_t mlen;           \
}

typedef struct ws_header {
    union {
        struct {
            uint16_t unused;
            FOP_MASK;
        };
        struct {
            FOP_MASK;
            uint16_t elen;
        } extend;
    };
    uint32_t mask;
} ws_header;

int parse_ws_header(const uint8_t *buffer, uint16_t size, struct ws_header_info *info) {
    uint8_t fop;
    uint8_t len;
    ws_header ws_header;
    info->header_size = WS_HEADER_SIZE;
    if (size < info->header_size) {
        return info->header_size;
    }
    memcpy(&(ws_header.fop), buffer, WS_HEADER_SIZE);
    len = ws_header.mlen & 0x7f;
    if (len == 0x7f) {
        return -1;
    }
    if (len < 0x7e) {
        fop = ws_header.fop;
        info->mask = (ws_header.mlen & 0x80) != 0;
        info->payload_size = len;
    } else {
        info->header_size = EXTEND_WS_HEADER_SIZE;
        if (size < info->header_size) {
            return info->header_size;
        }
        memcpy(&(ws_header.extend), buffer, EXTEND_WS_HEADER_SIZE);
        fop = ws_header.extend.fop;
        info->mask = (ws_header.extend.mlen & 0x80) != 0;
        info->payload_size = htons(ws_header.extend.elen);
    }
    if (info->mask) {
        info->header_size += MASK_SIZE;
        if (size < info->header_size) {
            return info->header_size;
        }
        memcpy(&(info->mask_key), buffer + info->header_size - MASK_SIZE, MASK_SIZE);
    }
    info->fin = (fop & 0x80) != 0;
    info->rsv = (fop & 0x70) >> 4;
    info->op = fop & 0xf;
    return 0;
}

uint8_t *build_ws_header(struct ws_header_info *info, void *payload, uint16_t size) {
    uint8_t fop, *header;
    ws_header ws_header;
    memset(&ws_header, 0, sizeof(ws_header));
    fop = (info->fin ? 0x80 : 0) | ((info->rsv & 0x7) << 4) | (info->op & 0xf);
    if (size < 0x7e) {
        ws_header.fop = fop;
        ws_header.mlen = (info->mask ? 0x80 : 0) | (uint8_t) size;
        info->header_size = WS_HEADER_SIZE;
        header = &(ws_header.fop);
    } else {
        ws_header.extend.fop = fop;
        ws_header.extend.mlen = (info->mask ? 0x80 : 0) | 0x7e;
        ws_header.extend.elen = ntohs(size);
        info->header_size = EXTEND_WS_HEADER_SIZE;
        header = &(ws_header.extend.fop);
    }
    if (info->mask) {
        info->header_size += MASK_SIZE;
        ws_header.mask = info->mask_key;
    }
    return memcpy(payload - info->header_size, header, info->header_size);
}

void mask(void *buffer, uint16_t size, uint32_t mask_key) {
    uint16_t offset, max;
    uint32_t *masked = (uint32_t *) buffer;
    for (offset = 0, max = (size >> 2); offset < max; offset++, masked++) {
        *masked ^= mask_key;
    }
    for (offset = 0, max = (size & 0x3); offset < max; offset++) {
        ((uint8_t *) masked)[offset] ^= ((uint8_t *) &mask_key)[offset];
    }
}