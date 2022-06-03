#pragma once

#include <stdint.h>
#include "buffer.h"
#include <stdbool.h>

static const uint8_t SOCKS_VERSION = 0x05;

enum connectionMethod {
    METHOD_NO_AUTHENTICATION_REQUIRED = 0x00,
    METHOD_USERNAME_PASSWORD = 0x02,
    METHOD_NO_ACCEPTABLE_METHODS = 0xFF,
};

/*
 *  The client connects to the server, and sends a version
 *  identifier/method selection message:
 *
 *                 +----+----------+----------+
 *                 |VER | NMETHODS | METHODS  |
 *                 +----+----------+----------+
 *                 | 1  |    1     | 1 to 255 |
 *                 +----+----------+----------+
 *
 *  The VER field is set to X'05' for this version of the protocol.  The
 *  NMETHODS field contains the number of method identifier octets that
 *  appear in the METHODS field.
 */

enum connectionState {
    CONECTION_VERSION,
    CONECTION_NMETHODS,
    CONECTION_METHODS,
    CONECTION_DONE,
    CONECTION_ERROR_UNSUPPORTED_VERSION,
};

struct connectionParser {
    uint8_t selected_method;
    enum connectionState state;
    uint8_t remaining;
};

void connection_parser_init(struct connectionParser *parser);

enum connectionState connection_parse(struct connectionParser *parser, buffer *buf, bool *error);

/*
 *  The server selects from one of the methods given in METHODS, and
 *  sends a METHOD selection message:
 *
 *                       +----+--------+
 *                       |VER | METHOD |
 *                       +----+--------+
 *                       | 1  |   1    |
 *                       +----+--------+
 *
 *  If the selected METHOD is X'FF', none of the methods listed by the
 *  client are acceptable, and the client MUST close the connection.
 */
int generate_connection_response(buffer *buf, enum connectionMethod method);

const char * connection_error(enum connectionState state);

bool is_connection_finished(enum connectionState state, bool *error);