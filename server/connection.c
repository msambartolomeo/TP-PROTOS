#include <stdlib.h>
#include <stdio.h>
#include "connection.h"

void connection_parser_init(struct connection_parser *parser) {
    parser->methods_remaining = 0;
    parser->state = connection_version;
}

void connection_parse_byte(struct connection_parser *parser, uint8_t byte) {
    switch (parser->state) {
        case connection_version:
            parser->state = byte == SOCKS_VERSION ? connection_nmethods : connection_error_unsupported_version;
            break;
        case connection_nmethods:
            if (byte == 0x00) {
                parser->state = connection_done;
            } else {
                parser->methods_remaining = byte;
                parser->state = connection_methods;
            }
            break;
        case connection_methods:
            // TODO: save method with function or in parser struct
            parser->methods_remaining--;
            if (parser->methods_remaining == 0) {
                parser->state = connection_done;
            }
            break;
        case connection_done:
        case connection_error_unsupported_version:
            break;
        default:
            fprintf(stderr, "Unknown connection state: %d\n", parser->state);
            abort();
    }
}

bool connection_finished(enum connection_state state, bool *error) {
    if (state == connection_error_unsupported_version) {
        *error = true;
        return true;
    }
    return state == connection_done;
}

enum connection_state connection_parse(struct connection_parser *parser, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        connection_parse_byte(parser, b);
        if (connection_finished(parser->state, error)) {
            break;
        }
    }
    return parser->state;
}

int generate_connection_response(buffer *buf, uint8_t method) {
    size_t n;
    uint8_t *buf_ptr = buffer_write_ptr(buf, &n);
    if (n < 2) {
        return -1;
    }

    buf_ptr[0] = SOCKS_VERSION;
    buf_ptr[1] = method;
    buffer_write_adv(buf, 2);
    return 2;
}

const char * connection_error(enum connection_state state) {
    if (state == connection_error_unsupported_version) {
        return "Unsupported version";
    }
    return "";
}