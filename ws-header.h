#ifndef WSS_PROXY_WS_HEADER_H
#define WSS_PROXY_WS_HEADER_H

#include <stdint.h>

struct ws_header_info {
    uint8_t fin: 1;
    uint8_t rsv: 3;
    uint8_t op: 4;
    uint8_t mask: 1;
    uint8_t header_size: 4;
    uint16_t payload_size;
    uint32_t mask_key;
};

enum ws_op {
    OP_CONTINUATION = 0x0,
    OP_TEXT = 0x1,
    OP_BINARY = 0x2,
    OP_CLOSE = 0x8,
    OP_PING = 0x9,
    OP_PONG = 0xa,
};

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define WS_HEADER_SIZE 2
#define EXTEND_WS_HEADER_SIZE 4
#define MASK_SIZE 4
#define MAX_WS_HEADER_SIZE (EXTEND_WS_HEADER_SIZE + MASK_SIZE)

/**
 * @return 0 when success, >0 for bytes required, -1 for unsupported 64 bits length
 */
int parse_ws_header(const uint8_t *buffer, uint16_t size, struct ws_header_info *info);

/**
 * @param payload there should be ws header before payload, use MAX_WS_HEADER_SIZE if unsure
 * @return start of the websocket frame
 */
uint8_t *build_ws_header(struct ws_header_info *info, void *payload, uint16_t payload_size);

void mask(void *buffer, uint16_t size, uint32_t mask_key);

#endif // WSS_PROXY_WS_HEADER_H
