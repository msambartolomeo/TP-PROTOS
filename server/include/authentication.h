#pragma once

#include "buffer.h"
#include <stdbool.h>
#include <stdint.h>

static const uint8_t AUTHENTICATION_VERSION = 0x01;

/*
 *  Once the SOCKS V5 server has started, and the client has selected the
 *  Username/Password Authentication protocol, the Username/Password
 *  subnegotiation begins.  This begins with the client producing a
 *  Username/Password request:
 *
 *          +----+------+----------+------+----------+
 *          |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *          +----+------+----------+------+----------+
 *          | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *          +----+------+----------+------+----------+

 *  The VER field contains the current version of the subnegotiation,
 *  which is X'01'. The ULEN field contains the length of the UNAME field
 *  that follows. The UNAME field contains the username as known to the
 *  source operating system. The PLEN field contains the length of the
 *  PASSWD field that follows. The PASSWD field contains the password
 *  association with the given UNAME.
 */

enum authentication_state {
    AUTHENTICATION_STATE_VERSION,
    AUTHENTICATION_USERNAME_LENGTH,
    AUTHENTICATION_USERNAME,
    AUTHENTICATION_PASSWORD_LENGTH,
    AUTHENTICATION_PASSWORD,
    AUTHENTICATION_DONE,
    AUTHENTICATION_ERROR_UNSUPPORTED_VERSION,
};

typedef struct credentials {
    uint8_t username[256];
    uint8_t password[256];
} authentication_credentials;

struct authentication_parser {
    enum authentication_state state;
    uint8_t remaining;
    uint8_t * pointer;
    authentication_credentials credentials;
};

void authentication_parser_init(struct authentication_parser * parser);

enum authentication_state
authentication_parse(struct authentication_parser * parser, buffer * buf,
                     bool * error);

enum authentication_status {
    AUTHENTICATION_STATUS_OK = 0,
    AUTHENTICATION_STATUS_FAILED = 1,
};

/*
 *  The server verifies the supplied UNAME and PASSWD, and sends the
 *  following response:
 *
 *                       +----+--------+
 *                       |VER | STATUS |
 *                       +----+--------+
 *                       | 1  |   1    |
 *                       +----+--------+
 *
 *  A STATUS field of X'00' indicates success. If the server returns a
 *  `failure' (STATUS value other than X'00') status, it MUST close the
 *  connection.
 */
int generate_authentication_response(buffer * buf, uint8_t status);

const char * authentication_error(enum authentication_state state);

bool is_authentication_finished(enum authentication_state state, bool * error);
