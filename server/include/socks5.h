#pragma once
#include "authentication.h"
#include "buffer.h"
#include "connection.h"
#include "pswrdDiss.h"
#include "request.h"
#include "selector.h"
#include "stm.h"
#include "users.h"
#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t SOCKS_VERSION = 0x05;

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

struct copy {
    int fd;
    buffer *rb, *wb;
    fd_interest interests;
    fd_interest connection_interests;
    struct copy * other;
};

typedef struct socks5_connection {
    // Datos del cliente
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_socket;
    int client_interests; // Si tenemos máquina de estados no hace falta

    // Datos del origin
    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_socket;
    int origin_domain;
    int origin_interests;

    // Para resolucion de nombres
    struct addrinfo * resolved_addr;
    struct addrinfo * resolved_addr_current;

    // Buffers
    uint8_t * raw_buffer_a;
    uint8_t * raw_buffer_b;
    buffer read_buffer;
    buffer write_buffer;

    struct state_machine stm;

    union {
        struct connection_parser connection;
        struct authentication_parser authentication;
        struct request_parser request;
    } parser;

    // estructura para contraseñas de pop
    struct pop3_parser pop3;

    // estructuras para usar en el estado de copy
    struct copy client_copy;
    struct copy origin_copy;

    // usuario que creo la conexion
    const struct user * user;

    bool dont_close;

    // TODO: Parsers?
    // En la implementación de Coda también tiene ClientAddr, ServerAddr,
    // resolución de nombre de origen, estados de origen y de destino, buffers
    // (tanto raw como struct), y cantidad de referencias al struct.
} socks5_connection;

const struct state_definition * get_socks5_states();

void socks_change_buf_size(uint32_t size);
uint32_t socks_get_buf_size();
