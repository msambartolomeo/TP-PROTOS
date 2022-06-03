#include <string.h>
#include "request.h"
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>

void request_parser_init(struct requestParser *parser) {
    parser->state = REQUEST_VERSION;
    parser->remaining = 0;
    parser->request.command = 0;
    parser->request.address_type = 0;
    parser->request.port = 0;
}

static enum requestState cmd(struct requestParser *parser, uint8_t byte) {
    switch (byte) {
        case COMMAND_CONNECT:
        case COMMAND_BIND:
        case COMMAND_UDP_ASSOCIATE:
            parser->request.command = byte;
            return REQUEST_RESERVED;
        default:
            return REQUEST_ERROR_UNSUPPORTED_COMMAND;
    }
}

static enum requestState addr_type(struct requestParser *parser, uint8_t byte) {
    parser->request.address_type = byte;
    parser->pointer = 0;

    switch (parser->request.address_type) {
        case ADDRESS_TYPE_IPV4:
            parser->remaining = 4;
            memset(&(parser->request.destination.ipv4),0, sizeof(parser->request.destination.ipv4));
            parser->request.destination.ipv4.sin_family = AF_INET;
            parser->pointer = (uint8_t *) &(parser->request.destination.ipv4.sin_addr);
            return REQUEST_DST_ADDRESS;
        case ADDRESS_TYPE_IPV6:
            parser->remaining = 16;
            memset(&(parser->request.destination.ipv6),0, sizeof(parser->request.destination.ipv6));
            parser->request.destination.ipv6.sin6_family = AF_INET6;
            parser->pointer = parser->request.destination.ipv6.sin6_addr.s6_addr;
            return REQUEST_DST_ADDRESS;
        case ADDRESS_TYPE_DOMAINNAME:
            parser->pointer = parser->request.destination.fqdn;
            return REQUEST_DST_ADDRESS_FQDN;
        default:
            return REQUEST_ERROR_UNSUPPORTED_ADDRESS_TYPE;
    }
}

static void request_parse_byte(struct requestParser *parser, uint8_t byte) {
    switch (parser->state) {
        case REQUEST_VERSION:
            parser->state = byte == SOCKS_VERSION ? REQUEST_COMMAND : REQUEST_ERROR_UNSUPPORTED_VERSION;
            break;
        case REQUEST_COMMAND:
            parser->state = cmd(parser, byte);
            break;
        case REQUEST_RESERVED:
            parser->state = byte == 0x00 ? REQUEST_ADDRESS_TYPE : REQUEST_ERROR_MISSING_RSV;
            break;
        case REQUEST_ADDRESS_TYPE:
            parser->state = addr_type(parser, byte);
            break;
        case REQUEST_DST_ADDRESS_FQDN:
            if (byte == 0x00) {
                parser->remaining = 2;
                parser->state = REQUEST_DST_PORT;
                parser->pointer = (uint8_t *) &(parser->request.port);
            } else {
                parser->remaining = byte;
                parser->request.destination.fqdn[parser->remaining] = 0;
                parser->state = REQUEST_DST_ADDRESS;
            }
            break;
        case REQUEST_DST_ADDRESS:
            *(parser->pointer++) = byte;

            parser->remaining--;
            if (parser->remaining == 0) {
                parser->remaining = 2;
                parser->pointer = (uint8_t *) &(parser->request.port);
                parser->state = REQUEST_DST_PORT;
            }
            break;
        case REQUEST_DST_PORT:
            *(parser->pointer++) = byte;

            parser->remaining--;
            if (parser->remaining == 0) {
                parser->state = REQUEST_DONE;
            }
            break;
        case REQUEST_DONE:
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_COMMAND:
        case REQUEST_ERROR_UNSUPPORTED_ADDRESS_TYPE:
            break;
        default:
            fprintf(stderr, "Unknown connection state: %d\n", parser->state);
            abort();
    }
}

enum requestState request_parse(struct requestParser *parser, buffer *buf, bool *error) {
    while (buffer_can_read(buf)) {
        const uint8_t b = buffer_read(buf);
        request_parse_byte(parser, b);
        if (is_request_finished(parser->state, error)) {
            break;
        }
    }
    return parser->state;
}

static uint8_t *get_address_pointer_and_length(socksResponse *response, size_t *length) {
    switch (response->address_type) {
        case ADDRESS_TYPE_IPV4:
            *length = 4;
            return (uint8_t *) &(response->address.ipv4.sin_addr);
        case ADDRESS_TYPE_DOMAINNAME:
            *length = strlen((char *) response->address.fqdn);
            return response->address.fqdn;
        case ADDRESS_TYPE_IPV6:
            *length = 16;
            return response->address.ipv6.sin6_addr.s6_addr;
    }
    return NULL;
}

size_t generate_response(buffer *buf, socksResponse *response) {
    size_t n;
    uint8_t *buf_ptr = buffer_write_ptr(buf, &n);

    size_t length;
    uint8_t *pointer = get_address_pointer_and_length(response, &length);

    if (n < length + 6 || pointer == NULL) {
        return -1;
    }

    *buf_ptr++ = SOCKS_VERSION;
    *buf_ptr++ = response->status;
    *buf_ptr++ = 0x00;
    *buf_ptr++ = response->address_type;
    strncpy((char *) buf_ptr, (char *) pointer, length);
    buf_ptr += length;
    uint8_t *port_ptr = (uint8_t *) &(response->port);
    *buf_ptr++ = port_ptr[0];
    *buf_ptr++ = port_ptr[1];

    buffer_write_adv(buf, (ssize_t) length + 6);
    return length + 6;
}

const char * request_error(enum requestState state) {
    switch (state) {
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
            return "Unsupported version";
        case REQUEST_ERROR_UNSUPPORTED_COMMAND:
            return "Unsupported command";
        case REQUEST_ERROR_UNSUPPORTED_ADDRESS_TYPE:
            return "Unsupported address type";
        case REQUEST_ERROR_MISSING_RSV:
            return "Missing reserved byte";
        default:
            return "";
    }
}

bool is_request_finished(enum requestState state, bool *error) {
    switch (state) {
        case REQUEST_DONE:
            return true;
        case REQUEST_ERROR_UNSUPPORTED_VERSION:
        case REQUEST_ERROR_UNSUPPORTED_COMMAND:
        case REQUEST_ERROR_UNSUPPORTED_ADDRESS_TYPE:
            *error = true;
            return true;
        default:
            return false;
    }
}