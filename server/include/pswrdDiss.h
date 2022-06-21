#pragma once
#include "buffer.h"
#include <stdbool.h>
#include <stdint.h>

// all functions do not modify the buffer

/*
 * As defined in POP3 Extension Mechanism [rfc 2449] the max length of a command
 * is 255 octets including the CRLF, space and the command itself, so that
 * leaves us with a max length of 248 octets for the arguments.
 */
#define POP3_ARGUMENT_LENGTH 249
#define POP3_COMMAND_LENGTH 5

enum pop3_state {
    POP3_GREETING,
    POP3_USER_COMMAND,
    POP3_USER,
    POP3_PASS_COMMAND,
    POP3_PASS,
    POP3_ERROR,
    POP3_DONE,
};

struct pop3 {
    uint8_t user[POP3_ARGUMENT_LENGTH];
    uint8_t pass[POP3_ARGUMENT_LENGTH];
};

struct pop3_parser {
    uint8_t buff[POP3_COMMAND_LENGTH];
    enum pop3_state state;
    struct pop3 info;
    uint8_t remaining;
    uint8_t * current;
};

void pop3_parser_init(struct pop3_parser * parser);

void skip_pop3_check(struct pop3_parser * parser);

// check if the server sends pop3 greeting (+OK)
enum pop3_state check_pop3(uint8_t * buf_ptr, ssize_t n,
                           struct pop3_parser * parser);

// checks if the client sends a user or pass pop3 command and saves the argument
enum pop3_state pop3_parse(uint8_t ** buf_ptr, ssize_t * n,
                           struct pop3_parser * parser);

bool do_pop3(enum pop3_state state);

bool dissector_is_on();

void change_dissector_state(bool state);
