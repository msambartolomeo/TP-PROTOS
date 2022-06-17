#include "pswrdDiss.h"
#include <string.h>
#include <ctype.h>

void pop3_parser_init(struct pop3_parser *parser) {
    parser->state = POP3_GREETING;
    parser->remaining = 3;
    parser->current = parser->buff;
}

static void reset_user_phase(struct pop3_parser *parser) {
    parser->state = POP3_USER_COMMAND;
    parser->remaining = 5;
    parser->current = parser->buff;
}

static void reset_pass_phase(struct pop3_parser *parser) {
    parser->state = POP3_PASS_COMMAND;
    parser->remaining = 5;
    parser->current = parser->buff;
}

enum pop3State check_pop3(buffer *buf, struct pop3_parser *parser) {
    if (parser->state != POP3_GREETING) {
        return POP3_ERROR;
    }

    size_t n;
    uint8_t *buf_ptr = buffer_read_ptr(buf, &n);

    while (n-- > 0 && parser->remaining-- > 0) {
        *parser->current++ = *buf_ptr++;
    }

    if (parser->remaining == 0) {
        if (parser->buff[0] == '+' && parser->buff[1] == 'O' && parser->buff[2] == 'K') {
            reset_user_phase(parser);
        } else {
            parser->state = POP3_DONE;
        }
    }

    return parser->state;
}

static enum pop3State check_pop3_client_byte(struct pop3_parser *parser, uint8_t byte) {
    switch (parser->state) {
        case POP3_USER_COMMAND:
            if (byte == '\r') {
                reset_user_phase(parser);
                return parser->state;
            }

            *parser->current++ = toupper(byte);
            parser->remaining--;

            if (parser->remaining == 0) {
                if (strncmp((char *) parser->buff, "USER ", 5) == 0) {
                    parser->remaining = POP3_ARGUMENT_LENGTH;
                    parser->current = parser->info.user;
                    parser->state = POP3_USER;
                } else {
                    reset_user_phase(parser);
                    return POP3_ERROR;
                }
            }
            break;
        case POP3_USER:
            if (byte == '\r' || parser->remaining == 0) {
                reset_pass_phase(parser);
                return parser->state;
            }

            *parser->current++ = byte;
            parser->remaining--;
            break;
        case POP3_PASS_COMMAND:
            if (byte == '\r') {
                reset_pass_phase(parser);
                return parser->state;
            }

            *parser->current++ = toupper(byte);
            parser->remaining--;

            if (parser->remaining == 0) {
                if (strncmp((char *) parser->buff, "PASS ", 5) == 0) {
                    parser->remaining = POP3_ARGUMENT_LENGTH;
                    parser->current = parser->info.pass;
                    parser->state = POP3_PASS;
                } else {
                    reset_pass_phase(parser);
                    return POP3_ERROR;
                }
            }
            break;
        case POP3_PASS:
            if (byte == '\r' || parser->remaining == 0) {
                // back to user in case auth fails
                reset_user_phase(parser);
                return POP3_DONE;
            }

            *parser->current++ = byte;
            parser->remaining--;
            break;
        case POP3_GREETING:
        case POP3_ERROR:
        case POP3_DONE:
        default:
            return POP3_ERROR;
    }
    return parser->state;
}

bool is_pop3_finished(enum pop3State state) {
    return state == POP3_DONE || state == POP3_ERROR;
}

enum pop3State check_pop3_client(buffer *buf, struct pop3_parser *parser) {
    size_t n;
    uint8_t *buf_ptr = buffer_read_ptr(buf, &n);

    enum pop3State state = parser->state;

    if (is_pop3_finished(state)) {
        return state;
    }

    for (; n > 0; n--, buf_ptr++) {
        // if theres an error with the line, ignore it
        if (state == POP3_ERROR && *buf_ptr != '\n') continue;
        // always ignore the end of line
        if (*buf_ptr == '\n') continue;

        state = check_pop3_client_byte(parser, *buf_ptr);

        if (state == POP3_DONE) return state;
    }
    return parser->state;
}
