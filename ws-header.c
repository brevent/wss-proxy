#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif
#include "ws-header.h"

/**
 * fop: fin:1, rsv:3, opcode: 4
 * mlen: mask: 1, length: 7
 */

typedef struct ws_header {
    union {
        struct {
            uint16_t unused;
            uint8_t fop;
            uint8_t mlen;
        } base;
        struct {
            uint8_t fop;
            uint8_t mlen;
            uint16_t elen;
        } extend;
    } u;
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
    memcpy(&(ws_header.u.base.fop), buffer, WS_HEADER_SIZE);
    len = ws_header.u.base.mlen & 0x7f;
    if (len == 0x7f) {
        return -1;
    }
    if (len <= MAX_CONTROL_FRAME_SIZE) {
        fop = ws_header.u.base.fop;
        info->mask = (ws_header.u.base.mlen & 0x80) != 0;
        info->payload_size = len;
    } else {
        info->header_size = EXTEND_WS_HEADER_SIZE;
        if (size < info->header_size) {
            return info->header_size;
        }
        memcpy(&(ws_header.u.extend), buffer, EXTEND_WS_HEADER_SIZE);
        fop = ws_header.u.extend.fop;
        info->mask = (ws_header.u.extend.mlen & 0x80) != 0;
        info->payload_size = htons(ws_header.u.extend.elen);
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

uint8_t *build_ws_header(struct ws_header_info *info, uint8_t *payload, uint16_t size) {
    uint8_t fop, *header;
    ws_header ws_header;
    memset(&ws_header, 0, sizeof(ws_header));
    fop = (info->fin ? 0x80 : 0) | ((info->rsv & 0x7) << 4) | (info->op & 0xf);
    if (size < 0x7e) {
        ws_header.u.base.fop = fop;
        ws_header.u.base.mlen = (info->mask ? 0x80 : 0) | (uint8_t) size;
        info->header_size = WS_HEADER_SIZE;
        header = &(ws_header.u.base.fop);
    } else {
        ws_header.u.extend.fop = fop;
        ws_header.u.extend.mlen = (info->mask ? 0x80 : 0) | 0x7e;
        ws_header.u.extend.elen = ntohs(size);
        info->header_size = EXTEND_WS_HEADER_SIZE;
        header = &(ws_header.u.extend.fop);
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