#pragma once

#include <stdint.h>
#include "buffer.h"
#include <stdbool.h>
#include <netinet/in.h>

static const uint8_t SOCKS_VERSION = 0x05;

/*
 *  The SOCKS request is formed as follows:
 *
 *     +----+-----+-------+------+----------+----------+
 *     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *     +----+-----+-------+------+----------+----------+
 *     | 1  |  1  | X'00' |  1   | Variable |    2     |
 *     +----+-----+-------+------+----------+----------+
 *
 *  Where:
 *
 *       o  VER    protocol version: X'05'
 *       o  CMD
 *          o  CONNECT X'01'
 *          o  BIND X'02'
 *          o  UDP ASSOCIATE X'03'
 *       o  RSV    RESERVED
 *       o  ATYP   address type of following address
 *          o  IP V4 address: X'01'
 *          o  DOMAINNAME: X'03'
 *          o  IP V6 address: X'04'
 *       o  DST.ADDR       desired destination address
 *       o  DST.PORT desired destination port in network octet
 *           order
 */

enum socksCommand {
    COMMAND_CONNECT = 0x01,
    COMMAND_BIND = 0x02,
    COMMAND_UDP_ASSOCIATE = 0x03,
};

enum socksAddressType {
    ADDRESS_TYPE_IPV4 = 0x01,
    ADDRESS_TYPE_DOMAINNAME = 0x03,
    ADDRESS_TYPE_IPV6 = 0x04,
};

enum requestState {
    REQUEST_VERSION,
    REQUEST_COMMAND,
    REQUEST_RESERVED,
    REQUEST_ADDRESS_TYPE,
    REQUEST_DST_ADDRESS_FQDN,
    REQUEST_DST_ADDRESS,
    REQUEST_DST_PORT,
    REQUEST_DONE,
    REQUEST_ERROR_UNSUPPORTED_VERSION,
    REQUEST_ERROR_UNSUPPORTED_COMMAND,
    REQUEST_ERROR_UNSUPPORTED_ADDRESS_TYPE,
};

union socksAddr {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    char fqdn[256];
};

typedef struct request {
    enum socksCommand command;
    enum socksAddressType address_type;
    union socksAddr destination;
    in_port_t port;
} socks_request;

struct requestParser {
    struct request request;
    enum requestState state;
    uint8_t address_type_remaining;
};

/*
 *  The SOCKS request information is sent by the client as soon as it has
 *  established a connection to the SOCKS server, and completed the
 *  authentication negotiations.  The server evaluates the request, and
 *  returns a reply formed as follows:
 *
 *       +----+-----+-------+------+----------+----------+
 *       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *       +----+-----+-------+------+----------+----------+
 *       | 1  |  1  | X'00' |  1   | Variable |    2     |
 *       +----+-----+-------+------+----------+----------+
 *
 *    Where:
 *
 *         o  VER    protocol version: X'05'
 *         o  REP    Reply field:
 *            o  X'00' succeeded
 *            o  X'01' general SOCKS server failure
 *            o  X'02' connection not allowed by ruleset
 *            o  X'03' Network unreachable
 *            o  X'04' Host unreachable
 *            o  X'05' Connection refused
 *            o  X'06' TTL expired
 *            o  X'07' Command not supported
 *            o  X'08' Address type not supported
 *            o  X'09' to X'FF' unassigned
 *         o  RSV    RESERVED
 *         o  ATYP   address type of following address
 *            o  IP V4 address: X'01'
 *            o  DOMAINNAME: X'03'
 *            o  IP V6 address: X'04'
 *         o  BND.ADDR       server bound address
 *         o  BND.PORT       server bound port in network octet order
 */

enum socksResponseStatus {
    STATUS_SUCCEDED = 0x00,
    STATUS_GENERAL_SERVER_FAILURE = 0x01,
    STATUS_CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
    STATUS_NETWORK_UNREACHABLE = 0x03,
    STATUS_HOST_UNREACHABLE = 0x04,
    STATUS_CONNECTION_REFUSED = 0x05,
    STATUS_TTL_EXPIRED = 0x06,
    STATUS_COMMAND_NOT_SUPPORTED = 0x07,
    STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

void request_parser_init(struct requestParser *parser);

enum requestState request_parse(struct requestParser *parser, buffer *buf, bool *error);

int generate_response(buffer *buf /* TODO: arguments */);

const char * request_error(enum requestState state);

bool is_request_finished(enum requestState state, bool *error);