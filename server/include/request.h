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

enum socks_command {
    socks_command_connect = 0x01,
    socks_command_bind = 0x02,
    socks_command_udp_associate = 0x03,
};

enum socks_address_type {
    socks_address_type_ipv4 = 0x01,
    socks_address_type_domainname = 0x03,
    socks_address_type_ipv6 = 0x04,
};

enum request_state {
    request_version,
    request_command,
    request_reserved,
    request_address_type,
    request_destination_address_fqdn,
    request_destination_address,
    request_destination_port,
    request_done,
    request_error_unsupported_version,
    request_error_unsupported_command,
    request_error_unsupported_address_type,
};

union socks_addr {
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    char fqdn[256];
};

typedef struct request {
    enum socks_command command;
    enum socks_address_type address_type;
    union socks_addr destination;
    in_port_t port;
} socks_request;

struct request_parser {
    socks_request request;
    enum request_state state;
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

enum socks_response_status {
    status_succeeded = 0x00,
    status_general_server_failure = 0x01,
    status_connection_not_allowed_by_ruleset = 0x02,
    status_network_unreachable = 0x03,
    status_host_unreachable = 0x04,
    status_connection_refused = 0x05,
    status_ttl_expired = 0x06,
    status_command_not_supported = 0x07,
    status_address_type_not_supported = 0x08,
};

void request_parser_init(struct request_parser *parser);

enum request_state request_parse(struct request_parser *parser, buffer *buf, bool *error);

int generate_response(buffer *buf /* TODO: arguments */);

const char * request_error(enum request_state state);

bool is_request_finished(enum request_state state, bool *error);