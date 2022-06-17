#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"
#include "socks5.h"

// all functions do not modify the buffer

/*
 * As defined in POP3 Extension Mechanism [rfc 2449] the max length of a command is 255 octets
 * including the CRLF, space and the command itself, so that leaves us with a max length of
 * 248 octets for the arguments.
*/
#define POP_ARGUMENT_LENGTH 248

enum pop3State {
    POP3_USER,
    POP3_USER_OK,
    POP3_PASS,
    POP3_PASS_OK,
    POP3_ERROR,
    POP3_DONE,
};

struct pop3 {
    uint8_t user[POP_ARGUMENT_LENGTH];
    uint8_t pass[POP_ARGUMENT_LENGTH];
    bool valid_user;
    bool valid_pass;
};

struct pop3_parser {
    enum pop3State state;
    struct pop3 info;
    uint8_t remaining;
    uint8_t *current;
};

// check if the server sends pop3 greeting (+OK)
bool check_pop3(buffer *buf);

// translates pop server response to bool (+OK true, -ERR false)
// if we know the server has already sent a pop3 greeting, then we only need
// to check the first character
enum pop3State check_pop3_ok(buffer *buf, struct pop3_parser *parser);

// checks if the client sends a user or pass pop3 command and saves the argument
enum pop3State check_pop3_client(buffer *buf, struct pop3_parser *parser);

void print_pop3_credentials(struct pop3_parser *parser, socks5_connection *conn);
