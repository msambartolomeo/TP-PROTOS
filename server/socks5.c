#include "socks5.h"
#include "logger.h"
#include "metrics.h"
#include "networkHandler.h"
#include "selector.h"
#include "stm.h"
#include "users.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_DEFAULT_SIZE 1024
uint32_t buf_size = BUFFER_DEFAULT_SIZE;

void socks_change_buf_size(uint32_t size) { buf_size = size; }

uint32_t socks_get_buf_size() { return buf_size; }

// CONNECTION_READ
static void connection_read_init(unsigned state, struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    connection_parser_init(&conn->parser.connection);
}

static unsigned connection_read(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct connection_parser * parser = &conn->parser.connection;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum connection_state parser_state =
        connection_parse(parser, &conn->read_buffer, &error);

    bool done = is_connection_finished(parser_state, &error);

    if (error) {
        fprintf(stderr, "%s", connection_error(parser_state));
        return ERROR;
    }

    if (done) {
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE) ||
            generate_connection_response(&conn->write_buffer,
                                         parser->selected_method) == -1) {
            return ERROR;
        }
        return CONNECTION_WRITE;
    }

    return CONNECTION_READ;
}

// CONNECTION_WRITE

static unsigned connection_write(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;

    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&conn->write_buffer, &count);

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

static void authentication_read_init(unsigned state,
                                     struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    authentication_parser_init(&conn->parser.authentication);
}

static unsigned authentication_read(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct authentication_parser * parser = &conn->parser.authentication;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum authentication_state parser_state =
        authentication_parse(parser, &conn->read_buffer, &error);

    bool done = is_authentication_finished(parser_state, &error);

    if (error) {
        fprintf(stderr, "%s", authentication_error(parser_state));
        return ERROR;
    }

    if (done) {
        conn->user = authenticate_user(&parser->credentials);
        enum authentication_status status = conn->user == NULL
                                                ? AUTHENTICATION_STATUS_FAILED
                                                : AUTHENTICATION_STATUS_OK;
        if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE) ||
            generate_authentication_response(&conn->write_buffer, status) ==
                -1) {
            return ERROR;
        }
        return AUTHENTICATION_WRITE;
    }

    return AUTHENTICATION_READ;
}

// AUTHENTICATION_WRITE

static unsigned authentication_write(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;

    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&conn->write_buffer, &count);

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

enum socks_response_status connect_error_to_socks(const int e) {
    switch (e) {
    case 0:
        return STATUS_SUCCEDED;
    case ECONNREFUSED:
        return STATUS_CONNECTION_REFUSED;
    case EHOSTUNREACH:
        return STATUS_HOST_UNREACHABLE;
    case ENETUNREACH:
        return STATUS_NETWORK_UNREACHABLE;
    case ETIMEDOUT:
        return STATUS_TTL_EXPIRED;
    default:
        return STATUS_GENERAL_SERVER_FAILURE;
    }
}

static unsigned setup_response_error(struct request_parser * parser,
                                     enum socks_response_status status,
                                     socks5_connection * conn,
                                     struct selector_key * key) {
    parser->response.status = status;
    parser->response.address_type = parser->request.address_type;
    parser->response.port = parser->request.port;
    parser->response.address = parser->request.destination;

    if (SELECTOR_SUCCESS !=
            selector_set_interest(key->s, conn->client_socket, OP_WRITE) ||
        generate_response(&conn->write_buffer, &parser->response) == -1) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

static unsigned init_connection(struct request_parser * parser,
                                socks5_connection * conn,
                                struct selector_key * key) {
    conn->origin_socket =
        socket(conn->origin_domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (conn->origin_socket == -1) {
        return ERROR;
    }

    if (connect(conn->origin_socket, (struct sockaddr *)&conn->origin_addr,
                conn->origin_addr_len) < 0) {
        if (errno == EINPROGRESS) {
            // key es la del cliente
            if (SELECTOR_SUCCESS !=
                selector_set_interest(key->s, conn->client_socket, OP_NOOP)) {
                return ERROR;
            }
            if (SELECTOR_SUCCESS !=
                selector_register(key->s, conn->origin_socket,
                                  get_connection_fd_handler(), OP_WRITE,
                                  conn)) {
                return ERROR;
            }
            return REQUEST_CONNECT;
        }
        perror("connect");
        return setup_response_error(parser, connect_error_to_socks(errno), conn,
                                    key);
    }
    // connection was instantly established
    if (SELECTOR_SUCCESS !=
        selector_set_interest(key->s, conn->client_socket, OP_NOOP)) {
        return ERROR;
    }
    if (SELECTOR_SUCCESS != selector_register(key->s, conn->origin_socket,
                                              get_connection_fd_handler(),
                                              OP_WRITE, conn)) {
        return ERROR;
    }
    return REQUEST_CONNECT;
}

static void * request_resolv_thread(void * arg) {
    struct selector_key * key = (struct selector_key *)arg;
    socks5_connection * conn = (socks5_connection *)key->data;
    int ret;

    pthread_detach(pthread_self());
    struct addrinfo hint = {.ai_family = AF_UNSPEC,
                            .ai_socktype = SOCK_STREAM,
                            .ai_flags = AI_PASSIVE,
                            .ai_protocol = 0,
                            .ai_canonname = NULL,
                            .ai_addr = NULL,
                            .ai_next = NULL};
    char buf[7];
    snprintf(buf, sizeof buf, "%d", ntohs(conn->parser.request.request.port));

    ret = getaddrinfo((char *)conn->parser.request.request.destination.fqdn,
                      buf, &hint, &conn->resolved_addr);
    if (ret) {
        fprintf(stderr, "unable to get address info: %s", gai_strerror(ret));
        freeaddrinfo(conn->resolved_addr);
        conn->resolved_addr = NULL;
    }

    conn->resolved_addr_current = conn->resolved_addr;

    selector_notify_block(key->s, key->fd);

    free(arg);

    return 0;
}

// REQUEST_READ

static void request_read_init(unsigned state, struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    request_parser_init(&conn->parser.request);
}

static unsigned request_read(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct request_parser * parser = &conn->parser.request;

    if (!buffer_can_read(&conn->read_buffer)) {
        // TODO: no se si hay que manejar este caso
    }

    size_t count;
    uint8_t * bufptr = buffer_write_ptr(&conn->read_buffer, &count);

    ssize_t len = recv(conn->client_socket, bufptr, count, MSG_NOSIGNAL);

    if (len <= 0) {
        return ERROR;
    } else {
        buffer_write_adv(&conn->read_buffer, len);
    }

    bool error = false;
    enum request_state parser_state =
        request_parse(parser, &conn->read_buffer, &error);

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
                parser->request.destination.ipv4.sin_port =
                    parser->request.port;
                conn->origin_addr_len =
                    sizeof(parser->request.destination.ipv4);
                memcpy(&conn->origin_addr, &parser->request.destination,
                       sizeof(parser->request.destination.ipv4));
                return init_connection(parser, conn, key);
            case ADDRESS_TYPE_IPV6:
                conn->origin_domain = AF_INET6;
                parser->request.destination.ipv6.sin6_port =
                    parser->request.port;
                conn->origin_addr_len =
                    sizeof(parser->request.destination.ipv6);
                memcpy(&conn->origin_addr, &parser->request.destination,
                       sizeof(parser->request.destination.ipv6));
                return init_connection(parser, conn, key);
            case ADDRESS_TYPE_DOMAINNAME: {
                struct selector_key * k = malloc(sizeof(*key));
                if (k == NULL) {
                    return setup_response_error(
                        parser, STATUS_GENERAL_SERVER_FAILURE, conn, key);
                }
                memcpy(k, key, sizeof(*key));
                pthread_t tid;
                if (pthread_create(&tid, NULL, &request_resolv_thread, k) !=
                    0) {
                    free(k);
                    return setup_response_error(
                        parser, STATUS_GENERAL_SERVER_FAILURE, conn, key);
                }

                if (selector_set_interest_key(key, OP_NOOP) !=
                    SELECTOR_SUCCESS) {
                    return ERROR;
                }
                return REQUEST_RESOLV;
            }
            default:
                return ERROR;
            }
        case COMMAND_BIND:
        case COMMAND_UDP_ASSOCIATE:
            return setup_response_error(parser, STATUS_COMMAND_NOT_SUPPORTED,
                                        conn, key);
        }
    }

    return REQUEST_READ;
}

// REQUEST_RESOLV

static unsigned request_resolv(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct request_parser * parser = &conn->parser.request;

    if (conn->resolved_addr_current == NULL) {
        if (conn->resolved_addr != NULL) {
            freeaddrinfo(conn->resolved_addr);
            conn->resolved_addr = NULL;
            conn->resolved_addr_current = NULL;
        }
        return setup_response_error(parser, STATUS_HOST_UNREACHABLE, conn,
                                    key); // TODO: check response
    }

    conn->origin_domain = conn->resolved_addr_current->ai_family;
    conn->origin_addr_len = conn->resolved_addr_current->ai_addrlen;
    memcpy(&conn->origin_addr, conn->resolved_addr_current->ai_addr,
           conn->resolved_addr_current->ai_addrlen);
    conn->resolved_addr_current = conn->resolved_addr_current->ai_next;

    return init_connection(parser, conn, key);
}

// REQUEST_CONNECT

static unsigned request_connect(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct request_parser * parser = &conn->parser.request;

    int error = 0;
    if (getsockopt(conn->origin_socket, SOL_SOCKET, SO_ERROR, &error,
                   &(socklen_t){sizeof(int)})) {
        if (parser->request.address_type == ADDRESS_TYPE_DOMAINNAME) {
            freeaddrinfo(conn->resolved_addr);
            conn->resolved_addr = NULL;
        }
        return setup_response_error(parser, STATUS_GENERAL_SERVER_FAILURE, conn,
                                    key);
    }
    if (error) {
        if (parser->request.address_type == ADDRESS_TYPE_DOMAINNAME) {
            conn->dont_close = true;
            selector_unregister_fd(key->s, conn->origin_socket);
            conn->dont_close = false;
            close(conn->origin_socket);
            return request_resolv(key);
        }
        return setup_response_error(parser, connect_error_to_socks(error), conn,
                                    key);
    }

    if (parser->request.address_type == ADDRESS_TYPE_DOMAINNAME) {
        freeaddrinfo(conn->resolved_addr);
        conn->resolved_addr = NULL;
    }

    parser->response.status = STATUS_SUCCEDED;
    parser->response.port = parser->request.port;
    switch (conn->origin_domain) {
    case AF_INET:
        parser->response.address_type = ADDRESS_TYPE_IPV4;
        memcpy(&parser->response.address, &conn->origin_addr,
               sizeof(parser->response.address.ipv4));
        break;
    case AF_INET6:
        parser->response.address_type = ADDRESS_TYPE_IPV6;
        memcpy(&parser->response.address, &conn->origin_addr,
               sizeof(parser->response.address.ipv6));
        break;
    default:
        return setup_response_error(parser, STATUS_GENERAL_SERVER_FAILURE, conn,
                                    key);
    }

    if (SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP) ||
        SELECTOR_SUCCESS !=
            selector_set_interest(key->s, conn->client_socket, OP_WRITE) ||
        generate_response(&conn->write_buffer, &parser->response) == -1) {
        return ERROR;
    }
    return REQUEST_WRITE;
}

// REQUEST_WRITE

static unsigned request_write(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct request_parser * parser = &conn->parser.request;

    size_t count;
    uint8_t * bufptr = buffer_read_ptr(&conn->write_buffer, &count);

    ssize_t len = send(conn->client_socket, bufptr, count, MSG_NOSIGNAL);
    if (len == -1) {
        return ERROR;
    }
    buffer_read_adv(&conn->write_buffer, len);
    logger(LOG_ACCESS, conn);

    if (!buffer_can_read(&conn->write_buffer)) {
        if (parser->response.status != STATUS_SUCCEDED) {
            return DONE;
        }
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ) &&
            SELECTOR_SUCCESS ==
                selector_set_interest(key->s, conn->origin_socket, OP_READ)) {
            return COPY;
        }
        return ERROR;
    }

    return REQUEST_WRITE;
}

// COPY

static void copy_init(unsigned state, struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct copy * c = &conn->client_copy;

    c->fd = conn->client_socket;
    c->rb = &conn->read_buffer;
    c->wb = &conn->write_buffer;
    c->interests = OP_READ;
    c->connection_interests = OP_READ | OP_WRITE;
    c->other = &conn->origin_copy;

    c = &conn->origin_copy;

    c->fd = conn->origin_socket;
    c->rb = &conn->write_buffer;
    c->wb = &conn->read_buffer;
    c->interests = OP_READ;
    c->connection_interests = OP_READ | OP_WRITE;
    c->other = &conn->client_copy;

    if (dissector_is_on()) {
        pop3_parser_init(&conn->pop3);
        if (ntohs(conn->parser.request.request.port) == 110) {
            // if the port is POP3's default port, we can skip the origin check
            // to see if it's a POP3 server
            skip_pop3_check(&conn->pop3);
        }
    }
}

static unsigned copy_read(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct copy * c;
    if (key->fd == conn->client_socket) {
        c = &conn->client_copy;
    } else if (key->fd == conn->origin_socket) {
        c = &conn->origin_copy;
    } else {
        return ERROR;
    }

    if (!buffer_can_write(c->wb)) {
        c->interests &= ~OP_READ;
        c->interests &= c->connection_interests;
        selector_set_interest(key->s, key->fd, c->interests);
        return COPY;
    }

    size_t wbytes;
    uint8_t * bufptr = buffer_write_ptr(c->wb, &wbytes);

    ssize_t len = recv(key->fd, bufptr, wbytes, MSG_NOSIGNAL);
    if (len <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Shouldn't happen because of selector, but just in case
            return COPY;
        }
        if (len == -1) {
            // Read error, so we partialy close the connection
        }
        // len == 0, EOF reached, so we partialy close the connection
        c->connection_interests &= ~OP_READ;
        c->interests &= c->connection_interests;
        selector_set_interest(key->s, c->fd, c->interests);
        shutdown(c->fd, SHUT_RD);

        c->other->connection_interests &= ~OP_WRITE;
        if (!buffer_can_read(c->wb)) {
            c->other->interests &= c->other->connection_interests;
            selector_set_interest(key->s, c->other->fd, c->other->interests);
            shutdown(c->other->fd, SHUT_WR);
        }
        if (c->connection_interests == OP_NOOP &&
            c->other->connection_interests == OP_NOOP) {
            return DONE;
        }
        return COPY;
    }
    buffer_write_adv(c->wb, len);

    if (dissector_is_on()) {
        if (key->fd == conn->client_socket) {
            if (do_pop3(conn->pop3.state)) {
                while (len > 0) {
                    if (pop3_parse(&bufptr, &len, &conn->pop3) == POP3_DONE) {
                        logger(LOG_PASSWORD, conn);
                    }
                }
            }
        } else if (key->fd == conn->origin_socket) {
            if (conn->pop3.state == POP3_GREETING) {
                check_pop3(bufptr, len, &conn->pop3);
            }
        } else {
            return ERROR;
        }
    }

    c->other->interests |= OP_WRITE;
    c->other->interests &= c->other->connection_interests;
    selector_set_interest(key->s, c->other->fd, c->other->interests);

    return COPY;
}

static unsigned copy_write(struct selector_key * key) {
    socks5_connection * conn = (socks5_connection *)key->data;
    struct copy * c;
    if (key->fd == conn->client_socket) {
        c = &conn->client_copy;
    } else if (key->fd == conn->origin_socket) {
        c = &conn->origin_copy;
    } else {
        return ERROR;
    }

    size_t rbytes;
    uint8_t * bufptr = buffer_read_ptr(c->rb, &rbytes);

    ssize_t len = send(key->fd, bufptr, rbytes, MSG_NOSIGNAL);
    if (len == -1) {
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            // Cant write, so we close the connection
            return ERROR;
        }
        // Shouldn't happen because of selector, but just in case
        return COPY;
    }

    buffer_read_adv(c->rb, len);
    report_transfer_bytes(len);

    c->other->interests |= OP_READ;
    c->other->interests &= c->other->connection_interests;
    selector_set_interest(key->s, c->other->fd, c->other->interests);

    if (!buffer_can_read(c->rb)) {
        c->interests &= ~OP_WRITE;
        c->interests &= c->connection_interests;
        selector_set_interest(key->s, c->fd, c->interests);
        if (!(c->connection_interests & OP_WRITE)) {
            shutdown(c->fd, SHUT_WR);
        }
    }

    return COPY;
}

static const struct state_definition states[] = {
    {
        .state = CONNECTION_READ,
        .on_arrival = connection_read_init,
        .on_read_ready = connection_read,
    },
    {
        .state = CONNECTION_WRITE,
        .on_write_ready = connection_write,
    },
    {
        .state = AUTHENTICATION_READ,
        .on_arrival = authentication_read_init,
        .on_read_ready = authentication_read,
    },
    {
        .state = AUTHENTICATION_WRITE,
        .on_write_ready = authentication_write,
    },
    {
        .state = REQUEST_READ,
        .on_arrival = request_read_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv,
    },
    {
        .state = REQUEST_CONNECT,
        .on_write_ready = request_connect,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    {
        .state = ERROR,
    },
    {
        .state = DONE,
    }};

const struct state_definition * get_socks5_states() { return states; }
