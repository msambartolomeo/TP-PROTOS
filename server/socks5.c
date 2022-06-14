#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "stm.h"
#include "socks5.h"
#include "selector.h"
#include "users.h"
#include "networkHandler.h"

// CONNECTION_READ
static void connection_read_init(unsigned state, struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    connection_parser_init(&conn->parser.connection);
}

static unsigned connection_read(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct connectionParser * parser = &conn->parser.connection;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL); // TODO ver por que nosignal

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum connectionState parser_state = connection_parse(parser, &conn->read_buffer, &error);

    bool done = is_connection_finished(parser_state, &error);

    if (error) {
        fprintf(stderr, "%s", connection_error(parser_state));
        return ERROR;
    }

    if (done) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)
            || generate_connection_response(&conn->write_buffer, parser->selected_method) == -1) {
            return ERROR;
        }
        return CONNECTION_WRITE;
    }

    return CONNECTION_READ;
}

// CONNECTION_WRITE

static unsigned connection_write(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
            switch (conn->parser.connection.selected_method) {
                case METHOD_NO_AUTHENTICATION_REQUIRED:
                    return REQUEST_READ;
                case METHOD_USERNAME_PASSWORD:
                    return AUTHENTICATION_READ;
                case METHOD_NO_ACCEPTABLE_METHODS:
                    return DONE;
            }
        }
        return ERROR;
    }

    return CONNECTION_WRITE;
}

// AUTHENTICATION_READ

static void authentication_read_init(unsigned state, struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    authentication_parser_init(&conn->parser.authentication);
}

static unsigned authentication_read(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct authenticationParser * parser = &conn->parser.authentication;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum authenticationState parser_state = authentication_parse(parser, &conn->read_buffer, &error);

    bool done = is_authentication_finished(parser_state, &error);

    if (error) {
        fprintf(stderr, "%s", authentication_error(parser_state));
        return ERROR;
    }

    if (done) {
        enum authenticationStatus status = authenticate_user(&parser->credentials);
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)
            || generate_authentication_response(&conn->write_buffer, status) == -1) {
            return ERROR;
        }
        return AUTHENTICATION_WRITE;
    }

    return AUTHENTICATION_READ;
}

// AUTHENTICATION_WRITE

static unsigned authentication_write(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
            return REQUEST_READ;
        }
        return ERROR;
    }

    return AUTHENTICATION_WRITE;
}

// request auxiliar functions

static unsigned init_connection(struct requestParser *parser, socks5_connection *conn, struct selector_key *key) {
    conn->origin_socket = socket(conn->origin_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (conn->origin_socket == -1) {
        return ERROR;
    }

    if (connect(conn->origin_socket, (struct sockaddr *)&conn->origin_addr, conn->origin_addr_len) < 0) {
        if(errno == EINPROGRESS) {
            // key es la del cliente
            if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)) {
                return ERROR;
            }
            if (SELECTOR_SUCCESS != selector_register(key->s, conn->origin_socket, get_connection_fd_handler(), OP_WRITE, conn)) {
                return ERROR;
            }
            return REQUEST_CONNECT;
        }
        return ERROR;
    }
    return ERROR; // TODO: ?
}

static unsigned setup_response_error(struct requestParser *parser, enum socksResponseStatus status, socks5_connection *conn, struct selector_key *key) {
    parser->response.status = status;
    parser->response.address_type = parser->request.address_type;
    parser->response.port = parser->request.port;
    parser->response.address = parser->request.destination;

    if (SELECTOR_SUCCESS != selector_set_interest(key->s, conn->client_socket, OP_WRITE) || generate_response(&conn->write_buffer, &parser->response) == -1) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

// REQUEST_READ

static void request_read_init(unsigned state, struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    request_parser_init(&conn->parser.request);
}

static unsigned request_read(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct requestParser * parser = &conn->parser.request;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum requestState parser_state = request_parse(parser, &conn->read_buffer, &error);

    bool done = is_request_finished(parser_state, &error);

    if (error) {
        fprintf(stderr, "%s", request_error(parser_state));
        return ERROR;
    }

    if (done) {
        switch (parser->request.command) {
            case COMMAND_CONNECT:
                switch (parser->request.address_type) {
                    case ADDRESS_TYPE_IPV4:
                        conn->origin_domain = AF_INET;
                        parser->request.destination.ipv4.sin_port = parser->request.port;
                        conn->origin_addr_len = sizeof(parser->request.destination.ipv4);
                        memcpy(&conn->origin_addr, &parser->request.destination, sizeof(parser->request.destination.ipv4));
                        return init_connection(parser, conn, key);
                    case ADDRESS_TYPE_IPV6:
                        conn->origin_domain = AF_INET6;
                        parser->request.destination.ipv6.sin6_port = parser->request.port;
                        conn->origin_addr_len = sizeof(parser->request.destination.ipv6);
                        memcpy(&conn->origin_addr, &parser->request.destination, sizeof(parser->request.destination.ipv6));
                        return init_connection(parser, conn, key);
                    case ADDRESS_TYPE_DOMAINNAME:
                        return REQUEST_RESOLV;
                    default:
                        return ERROR;
                }
            case COMMAND_BIND:
            case COMMAND_UDP_ASSOCIATE:
                return setup_response_error(parser, STATUS_COMMAND_NOT_SUPPORTED, conn, key);
        }
    }

    return REQUEST_READ;
}

// REQUEST_WRITE

static unsigned request_write(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct requestParser * parser = &conn->parser.request;

    size_t count;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    if (!buffer_can_read(&conn->write_buffer)) {
        if (parser->response.status != STATUS_SUCCEDED) {
            return DONE;
        }
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
            return COPY;
        }
        return ERROR;
    }

    return AUTHENTICATION_WRITE;
}

// REQUEST_CONNECT

static unsigned request_connect(struct selector_key *key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct requestParser * parser = &conn->parser.request;

    int error = 0;
    if (getsockopt(conn->origin_socket, SOL_SOCKET, SO_ERROR, &error, &(socklen_t){sizeof(int)})) {
        return setup_response_error(parser, STATUS_GENERAL_SERVER_FAILURE, conn, key);
    }
    if(error) {
        return ERROR;
    }

    parser->response.status = STATUS_SUCCEDED;
    parser->response.port = parser->request.port;
    switch (conn->origin_domain) {
        case AF_INET:
            parser->response.address_type = ADDRESS_TYPE_IPV4;
            memcpy(&parser->response.address, &conn->origin_addr, sizeof(parser->response.address.ipv4));
            break;
        case AF_INET6:
            parser->response.address_type = ADDRESS_TYPE_IPV6;
            memcpy(&parser->response.address, &conn->origin_addr, sizeof(parser->response.address.ipv6));
            break;
        default:
            return setup_response_error(parser, STATUS_GENERAL_SERVER_FAILURE, conn, key);
    }

    if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP) || SELECTOR_SUCCESS != selector_set_interest(key->s, conn->client_socket, OP_WRITE) || generate_response(&conn->write_buffer, &parser->response) == -1) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

static const struct state_definition states[] = {
    {
        .state = CONNECTION_READ,
        .on_arrival = connection_read_init,
        .on_read_ready = connection_read,
    }, {
        .state = CONNECTION_WRITE,
        .on_write_ready = connection_write,
    }, {
        .state = AUTHENTICATION_READ,
        .on_arrival = authentication_read_init,
        .on_read_ready = authentication_read,
    }, {
        .state = AUTHENTICATION_WRITE,
        .on_write_ready = authentication_write,
    }, {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    }, {
        .state = REQUEST_RESOLV,
    }, {
        .state = REQUEST_CONNECT,
        .on_write_ready = request_connect,
    }, {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    }, {
        .state = COPY,
    }, {
        .state = ERROR,
    }, {
        .state = DONE,
    }
};

const struct state_definition * get_socks5_states() {
    return states;
}
