#include "pswrdDiss.h"
#include <ctype.h>
#include <string.h>

static bool dissector_state = true;

bool dissector_is_on() { return dissector_state; }

void change_dissector_state(bool state) { dissector_state = state; }

void pop3_parser_init(struct pop3_parser * parser) {
    parser->state = POP3_GREETING;
    parser->remaining = 3;
    parser->current = parser->buff;
}

static void reset_phase(struct pop3_parser * parser, enum pop3_state state) {
    parser->state = state;
    parser->remaining = 5;
    parser->current = parser->buff;
}

void skip_pop3_check(struct pop3_parser * parser) {
    reset_phase(parser, POP3_USER_COMMAND);
}

enum pop3_state check_pop3(uint8_t * buf_ptr, ssize_t n,
                           struct pop3_parser * parser) {
    if (parser->state != POP3_GREETING) {
        return POP3_ERROR;
    }

    for (; n > 0 && parser->remaining > 0; n--, parser->remaining--) {
        *parser->current++ = *buf_ptr++;
    }

    if (parser->remaining == 0) {
        if (parser->buff[0] == '+' && parser->buff[1] == 'O' &&
            parser->buff[2] == 'K') {
            reset_phase(parser, POP3_USER_COMMAND);
        } else {
            parser->state = POP3_DONE;
        }
    }

    return parser->state;
}

static enum pop3_state pop3_parse_command(struct pop3_parser * parser,
                                          uint8_t byte, enum pop3_state state) {
    if (byte == '\n' && parser->remaining == 5) {
        // ignore \n if the user was using CRLF
        return parser->state;
    }
    if (byte == '\r' || byte == '\n') {
        reset_phase(parser, POP3_USER_COMMAND);
        return parser->state;
    }

    *parser->current++ = toupper(byte);
    parser->remaining--;

    if (parser->remaining == 0) {
        parser->remaining = POP3_ARGUMENT_LENGTH - 1;
        if (state == POP3_PASS_COMMAND &&
            strncmp((char *)parser->buff, "PASS ", 5) == 0) {
            parser->current = parser->info.pass;
            parser->state = POP3_PASS;
        } else if (strncmp((char *)parser->buff, "USER ", 5) == 0) {
            parser->current = parser->info.user;
            parser->state = POP3_USER;
        } else {
            reset_phase(parser, state);
            return POP3_ERROR;
        }
    }
    return parser->state;
}

static enum pop3_state pop3_parse_argument(struct pop3_parser * parser,
                                           uint8_t byte,
                                           enum pop3_state state) {
    if (byte == '\r' || byte == '\n' || parser->remaining == 0) {
        *parser->current = 0;
        reset_phase(parser, POP3_PASS_COMMAND);
        switch (state) {
        case POP3_USER:
            return parser->state;
        case POP3_PASS:
            return POP3_DONE;
        default:
            return POP3_ERROR;
        }
    }

    *parser->current++ = byte;
    parser->remaining--;
    return parser->state;
}

static enum pop3_state pop3_parse_byte(struct pop3_parser * parser,
                                       uint8_t byte) {
    switch (parser->state) {
    case POP3_USER_COMMAND:
    case POP3_PASS_COMMAND:
        return pop3_parse_command(parser, byte, parser->state);
    case POP3_USER:
    case POP3_PASS:
        return pop3_parse_argument(parser, byte, parser->state);
    case POP3_GREETING:
    case POP3_ERROR:
    case POP3_DONE:
    default:
        return POP3_ERROR;
    }
}

bool do_pop3(enum pop3_state state) {
    return state != POP3_DONE && state != POP3_ERROR && state != POP3_GREETING;
}

enum pop3_state pop3_parse(uint8_t * buf_ptr, ssize_t * n,
                           struct pop3_parser * parser) {
    enum pop3_state state = parser->state;

    if (!do_pop3(state)) {
        return state;
    }

    for (; *n > 0; *n = *n - 1, buf_ptr++) {
        // if theres an error with the line, ignore it
        if (state == POP3_ERROR && *buf_ptr != '\n')
            continue;

        state = pop3_parse_byte(parser, *buf_ptr);

        if (state == POP3_DONE)
            return state;
    }

    if (*n > 0 && *buf_ptr == '\r') {
        *n = *n - 1;
        buf_ptr++;
    }
    if (*n > 0 && *buf_ptr == '\n') {
        *n = *n - 1;
        buf_ptr++;
    }

    return parser->state;
}
