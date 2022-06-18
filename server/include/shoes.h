#pragma once
#include <unistd.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netdb.h>
#include "buffer.h"
#include "stm.h"
#include "connection.h"
#include "authentication.h"
#include "request.h"
#include "selector.h"
#include "shoes_request.h"


#define BUFFER_DEFAULT_SIZE 1024
static const uint8_t SHOES_VERSION = 0x01;

enum socks5_state {
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    ERROR,
};

typedef struct shoes_connection {
    // Datos del cliente
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;
    int client_interests;

    //Buffers
    uint8_t raw_buffer_a[BUFFER_DEFAULT_SIZE];
    uint8_t raw_buffer_b[BUFFER_DEFAULT_SIZE];
    buffer read_buffer;
    buffer write_buffer;

    struct state_machine stm;

    union {
        struct authenticationParser authenticationParser;
        shoesParser shoesRequestParser;
    } parser;
} shoes_connection;

const struct state_definition * get_shoes_states();
