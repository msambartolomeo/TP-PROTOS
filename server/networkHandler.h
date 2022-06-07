#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <buffer.h>
#include <selector.h>

int network_handler();
void network_handler_cleanup();

#define BUFFER_DEFAULT_SIZE 1024

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
    
    // TODO: Parsers?
    // En la implementación de Coda también tiene ClientAddr, ServerAddr, resolución de nombre de origen, estados 
    // de origen y de destino, buffers (tanto raw como struct), y cantidad de referencias al struct.    
} socks5_connection;
