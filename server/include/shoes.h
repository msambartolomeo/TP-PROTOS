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
#include "shoes.h"


#define BUFFER_DEFAULT_SIZE 1024
static const uint8_t SHOES_VERSION = 0x01;

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
        shoesRequestParser shoesRequestParser;
    } parser;

} shoes_connection;
