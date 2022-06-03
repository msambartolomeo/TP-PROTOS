#include "authentication.h"
#include <stdio.h>
#include <stdlib.h>

void authentication_parser_init(struct authentication_parser *parser) {
    parser->state = authentication_version;
    parser->credentials.username[0] = 0;
    parser->credentials.password[0] = 0;
    parser->remaining = 0;
    parser->pointer = NULL;
}

void copy_byte_from_auth(struct authentication_parser *parser, uint8_t byte, enum authentication_state next_state) {
    *parser->pointer = byte;
    parser->remaining--;
    parser->pointer++;

    if (parser->remaining == 0) {
        parser->state = next_state;
        parser->pointer = NULL;
    }
}

void handle_length(struct authentication_parser *parser, uint8_t length, enum authentication_state next_state, enum authentication_state skip_state, uint8_t *pointer) {
    if (length == 0x0) {
        parser->state = skip_state;
    } else {
        parser->remaining = length;
        parser->state = next_state;
        parser->pointer = pointer;
    }
}

void authentication_parse_byte(struct authentication_parser *parser, uint8_t byte) {
    switch (parser->state) {
        case authentication_version:
            parser->state = byte == AUTHENTICATION_VERSION ? authentication_username_length : authentication_error_unsupported_version;
            break;
        case authentication_username_length:
            handle_length(parser, byte, authentication_username, authentication_password_length, parser->credentials.username);
            break;
        case authentication_username:
            copy_byte_from_auth(parser, byte, authentication_password_length);
            break;
        case authentication_password_length:
            handle_length(parser, byte, authentication_password, authentication_done, parser->credentials.password);
            break;
        case authentication_password:
            copy_byte_from_auth(parser, byte, authentication_done);
            break;
        case authentication_done:
        case authentication_error_unsupported_version:
            break;
        default:
            fprintf(stderr, "Unknown connection state: %d\n", parser->state);
            abort();
    }
}

enum authentication_state authentication_parse(struct authentication_parser *parser, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);

        authentication_parse_byte(parser, b);
        if (is_authentication_finished(parser->state, error)) {
            break;
        }
    }
    return parser->state;
}

int generate_authentication_response(buffer *buf, uint8_t status) {
    size_t n;
    uint8_t *buf_ptr = buffer_write_ptr(buf, &n);
    if (n < 2) {
        return -1;
    }

    buf_ptr[0] = AUTHENTICATION_VERSION;
    buf_ptr[1] = status;
    buffer_write_adv(buf, 2);
    return 2;
}

const char * authentication_error(enum authentication_state state) {
    if (state == authentication_error_unsupported_version) {
        return "Unsupported version";
    }
    return "";
}

bool is_authentication_finished(enum authentication_state state, bool *error) {
    if (state == authentication_error_unsupported_version) {
        *error = true;
        return true;
    }
    return state == authentication_done;
}