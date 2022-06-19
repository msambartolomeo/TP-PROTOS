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

enum shoes_state {
    SHOES_AUTHENTICATION_READ,
    SHOES_AUTHENTICATION_WRITE,
    SHOES_REQUEST_READ,
    SHOES_REQUEST_WRITE,
    SHOES_ERROR,
};

typedef struct shoes_connection {
    // Datos del cliente
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;
    int client_interests;

    bool isAuthenticated;

    //Buffers
    uint8_t raw_buffer_a[SHOES_BUFFER_DEFAULT_SIZE];
    uint8_t raw_buffer_b[SHOES_BUFFER_DEFAULT_SIZE];
    buffer read_buffer;
    buffer write_buffer;

    struct state_machine stm;

    union {
        struct authenticationParser authenticationParser;
        shoesParser shoesRequestParser;
    } parser;
} shoes_connection;

const struct state_definition * get_shoes_states();
