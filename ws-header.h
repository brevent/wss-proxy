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
    OP_CONTINUATION = 0,
    OP_TEXT = 1,
    OP_BINARY = 2,
    OP_CLOSE = 8,
    OP_PING = 9,
    OP_PONG = 10,
};

// https://www.iana.org/assignments/websocket/websocket.xhtml
enum ws_close_reason {
    CLOSE_NORMAL_CLOSURE = 1000,
    CLOSE_GOING_AWAY = 1001,
    CLOSE_PROTOCOL_ERROR = 1002,
    CLOSE_UNSUPPORTED_DATA = 1003,
    CLOSE_RESERVED = 1004,
    CLOSE_NO_STATUS_RCVD = 1005,
    CLOSE_ABNORMAL_CLOSURE = 1006,
    CLOSE_INVALID_FRAME_PAYLOAD_DATA = 1007,
    CLOSE_POLICY_VIOLATION = 1008,
    CLOSE_MESSAGE_TOO_BIG = 1009,
    CLOSE_MANDATORY_EXT = 1010,
    CLOSE_INTERNAL_ERROR = 1011,
    CLOSE_SERVICE_RESTART = 1012, // Alexey Melnikov, 2012/05/24
    CLOSE_TRY_AGAIN_LATER = 1013, // Alexey Melnikov, 2012/05/24
    CLOSE_BAD_GATEWAY = 1014, // Alexey Melnikov, 2016/09/08
    CLOSE_TLS_HANDSHAKE = 1015,
    CLOSE_UNAUTHORIZED = 3000, // Leo Tietz
    CLOSE_FORBIDDEN = 3003, // Ada Young
    CLOSE_TIMEOUT = 3008, // Morgan Jones
};

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define WS_HEADER_SIZE 2
#define EXTEND_WS_HEADER_SIZE 4
#define MASK_SIZE 4
#define MAX_WS_HEADER_SIZE (EXTEND_WS_HEADER_SIZE + MASK_SIZE)
#define MAX_CONTROL_FRAME_SIZE 125

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

#define unmask mask

#endif // WSS_PROXY_WS_HEADER_H
