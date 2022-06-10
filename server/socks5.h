#pragma once

// Estados de la maquina de estados general
// TODO: Agregar estados de socks5
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
