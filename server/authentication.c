#include "authentication.h"
#include <stdio.h>
#include <stdlib.h>

void authentication_parser_init(struct authentication_parser * parser) {
    parser->state = AUTHENTICATION_STATE_VERSION;
    parser->remaining = 0;
    parser->pointer = NULL;
}

static void copy_byte_from_auth(struct authentication_parser * parser,
                                uint8_t byte, enum authentication_state next) {
    *parser->pointer = byte;
    parser->remaining--;
    parser->pointer++;

    if (parser->remaining == 0) {
        parser->state = next;
        parser->pointer = NULL;
    }
}

static void handle_length(struct authentication_parser * parser, uint8_t length,
                          enum authentication_state next,
                          enum authentication_state skip, uint8_t * pointer) {
    if (length == 0x0) {
        parser->state = skip;
    } else {
        parser->remaining = length;
        parser->state = next;
        parser->pointer = pointer;
        parser->pointer[length] = 0;
    }
}

static void authentication_parse_byte(struct authentication_parser * parser,
                                      uint8_t byte) {
    switch (parser->state) {
    case AUTHENTICATION_STATE_VERSION:
        parser->state = byte == AUTHENTICATION_VERSION
                            ? AUTHENTICATION_USERNAME_LENGTH
                            : AUTHENTICATION_ERROR_UNSUPPORTED_VERSION;
        break;
    case AUTHENTICATION_USERNAME_LENGTH:
        handle_length(parser, byte, AUTHENTICATION_USERNAME,
                      AUTHENTICATION_PASSWORD_LENGTH,
                      parser->credentials.username);
        break;
    case AUTHENTICATION_USERNAME:
        copy_byte_from_auth(parser, byte, AUTHENTICATION_PASSWORD_LENGTH);
        break;
    case AUTHENTICATION_PASSWORD_LENGTH:
        handle_length(parser, byte, AUTHENTICATION_PASSWORD,
                      AUTHENTICATION_DONE, parser->credentials.password);
        break;
    case AUTHENTICATION_PASSWORD:
        copy_byte_from_auth(parser, byte, AUTHENTICATION_DONE);
        break;
    case AUTHENTICATION_DONE:
    case AUTHENTICATION_ERROR_UNSUPPORTED_VERSION:
        break;
    default:
        fprintf(stderr, "Unknown connection state: %d\n", parser->state);
        abort();
    }
}

enum authentication_state
authentication_parse(struct authentication_parser * parser, buffer * buf,
                     bool * error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);

        authentication_parse_byte(parser, b);
        if (is_authentication_finished(parser->state, error)) {
            break;
        }
    }
    return parser->state;
}

int generate_authentication_response(buffer * buf, uint8_t status) {
    size_t n;
    uint8_t * buf_ptr = buffer_write_ptr(buf, &n);
    if (n < 2) {
        return -1;
    }

    buf_ptr[0] = AUTHENTICATION_VERSION;
    buf_ptr[1] = status;
    buffer_write_adv(buf, 2);
    return 2;
}

const char * authentication_error(enum authentication_state state) {
    if (state == AUTHENTICATION_ERROR_UNSUPPORTED_VERSION) {
        return "Unsupported version";
    }
    return "";
}

bool is_authentication_finished(enum authentication_state state, bool * error) {
    if (state == AUTHENTICATION_ERROR_UNSUPPORTED_VERSION) {
        *error = true;
        return true;
    }
    return state == AUTHENTICATION_DONE;
}
