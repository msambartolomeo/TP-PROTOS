#pragma once
#include "authentication.h"
#include "buffer.h"
#include "connection.h"
#include "request.h"
#include "selector.h"
#include "shoes_request.h"
#include "stm.h"
#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define SHOES_BUFFER_DEFAULT_SIZE 1024
static const uint8_t SHOES_VERSION = 0x01;

enum shoes_state {
    SHOES_AUTHENTICATION_READ,
    SHOES_AUTHENTICATION_WRITE,
    SHOES_REQUEST_READ,
    SHOES_REQUEST_WRITE,
    SHOES_ERROR,
};

typedef struct shoes_connection {
    bool dont_close;

    // Datos del cliente
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;
    int client_interests;

    bool is_authenticated;

    // Buffers
    uint8_t raw_buffer_a[SHOES_BUFFER_DEFAULT_SIZE];
    uint8_t raw_buffer_b[SHOES_BUFFER_DEFAULT_SIZE];
    buffer read_buffer;
    buffer write_buffer;

    struct state_machine stm;

    union {
        struct authentication_parser authentication_parser;
        shoes_parser shoes_request_parser;
    } parser;
} shoes_connection;

const struct state_definition * get_shoes_states();
