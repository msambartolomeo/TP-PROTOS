#pragma once
#include <unistd.h>
#include <sys/socket.h>
#include <stdint.h>
#include "buffer.h"
#include "stm.h"
#include "connection.h"
#include "authentication.h"
#include "request.h"

#define BUFFER_DEFAULT_SIZE 1024

// Estados de la maquina de estados general
enum socks5_state {
    CONNECTION_READ,
    CONNECTION_WRITE,
    AUTHENTICATION_READ,
    AUTHENTICATION_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECT,
    REQUEST_WRITE,
    COPY,
    ERROR,
    DONE,
};

typedef struct socks5_connection {
    // Datos del cliente
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;
    int client_interests; // Si tenemos máquina de estados no hace falta

    // Datos del servidor
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    int server_socket;
    int server_interests;

    //Buffers
    uint8_t raw_buffer_a[BUFFER_DEFAULT_SIZE];
    uint8_t raw_buffer_b[BUFFER_DEFAULT_SIZE];
    buffer client_buf;
    buffer server_buf;

    struct state_machine stm;

    union {
        struct connectionParser connection;
        struct authenticationParser authentication;
        struct requestParser request;
    } parser;

    // TODO: Parsers?
    // En la implementación de Coda también tiene ClientAddr, ServerAddr, resolución de nombre de origen, estados
    // de origen y de destino, buffers (tanto raw como struct), y cantidad de referencias al struct.
} socks5_connection;

const struct state_definition * get_socks5_states();
