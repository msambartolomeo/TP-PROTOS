#include <stdlib.h>
#include <stdio.h>
#include "connection.h"
#include "socks5.h"
#include "users.h"

void connection_parser_init(struct connectionParser *parser) {
    parser->remaining = 0;
    parser->state = CONECTION_VERSION;
    parser->selected_method = METHOD_NO_ACCEPTABLE_METHODS;
}

static enum connectionMethod choose_method(enum connectionMethod current, enum connectionMethod new) {
    if (new == METHOD_USERNAME_PASSWORD || (!get_auth_state() && (new == METHOD_NO_AUTHENTICATION_REQUIRED && current != METHOD_USERNAME_PASSWORD))) {
        return new;
    }
    return current;
}

static void connection_parse_byte(struct connectionParser *parser, uint8_t byte) {
    switch (parser->state) {
        case CONECTION_VERSION:
            parser->state = byte == SOCKS_VERSION ? CONECTION_NMETHODS : CONECTION_ERROR_UNSUPPORTED_VERSION;
            break;
        case CONECTION_NMETHODS:
            if (byte == 0x00) {
                parser->state = CONECTION_DONE;
            } else {
                parser->remaining = byte;
                parser->state = CONECTION_METHODS;
            }
            break;
        case CONECTION_METHODS:
            parser->selected_method = choose_method(parser->selected_method, byte);

            parser->remaining--;
            if (parser->remaining == 0) {
                parser->state = CONECTION_DONE;
            }
            break;
        case CONECTION_DONE:
        case CONECTION_ERROR_UNSUPPORTED_VERSION:
            break;
        default:
            fprintf(stderr, "Unknown connection state: %d\n", parser->state);
            abort();
    }
}

bool is_connection_finished(enum connectionState state, bool *error) {
    if (state == CONECTION_ERROR_UNSUPPORTED_VERSION) {
        *error = true;
        return true;
    }
    return state == CONECTION_DONE;
}

enum connectionState connection_parse(struct connectionParser *parser, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        connection_parse_byte(parser, b);
        if (is_connection_finished(parser->state, error)) {
            break;
        }
    }
    return parser->state;
}

int generate_connection_response(buffer *buf, enum connectionMethod method) {
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

const char * connection_error(enum connectionState state) {
    if (state == CONECTION_ERROR_UNSUPPORTED_VERSION) {
        return "Unsupported version";
    }
    return "";
}
