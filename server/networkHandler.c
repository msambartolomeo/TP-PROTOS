#include <buffer.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/socket.h>

#include "networkHandler.h"
#include "selector.h"
#include "stm.h"
#include "socks5.h"
#include "shoes.h"
#include "metrics.h"

#define SELECTOR_TIMEOUT 100
#define DEFAULT_SOCKS_ADDR_IPV4 "0.0.0.0"
#define DEFAULT_SOCKS_ADDR_IPV6 "::"
#define DEFAULT_SHOES_ADDR_IPV4 "127.0.0.1"
#define DEFAULT_SHOES_ADDR_IPV6 "::1"

static fd_selector selector;

static void networkSelectorSignalHandler()
{
    printf("SIGCHLD SIGNAL");
}

void close_connection(socks5_connection * connection)
{
    int client_socket = connection->client_socket;
    int server_socket = connection->origin_socket;

    if (server_socket != -1)
    {
        selector_unregister_fd(selector, server_socket);
        close(server_socket);
    }
    if (client_socket != -1)
    {
        selector_unregister_fd(selector, client_socket);
        close(client_socket);
    }

    buffer_reset(&connection->read_buffer);
    buffer_reset(&connection->write_buffer);

    free(connection);

    report_closed_connection();
    printf("CONNECTION CLOSED\n");
}

void close_shoes_connection(shoes_connection * connection)
{
    int client_socket = connection->client_socket;

    if (client_socket != -1)
    {
        selector_unregister_fd(selector, client_socket);
        close(client_socket);
    }

    buffer_reset(&connection->read_buffer);
    buffer_reset(&connection->write_buffer);

    free(connection);

    printf("CONNECTION CLOSED\n");
}

// Hand connections to the state machine
static void connection_read(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *) key->data;
    const enum socks5_state state = stm_handler_read(&conn->stm, key);

    if (state == ERROR || state == DONE) {
        close_connection(conn);
    }
}

static void connection_write(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *) key->data;
    const enum socks5_state state = stm_handler_write(&conn->stm, key);

    if (state == ERROR || state == DONE) {
        close_connection(conn);
    }
}

static void connection_block(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *) key->data;
    const enum socks5_state state = stm_handler_block(&conn->stm, key);

    if (state == ERROR || state == DONE) {
        close_connection(conn);
    }
}

static void connection_close(struct selector_key *key) {
    socks5_connection *conn = (socks5_connection *) key->data;
    stm_handler_close(&conn->stm, key);
}

static const struct fd_handler connectionFdHandler = {
    .handle_read = connection_read,
    .handle_write = connection_write,
    .handle_block = connection_block,
    .handle_close = connection_close,
};

static void shoesConnectionRead(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    const enum shoes_state state = stm_handler_read(&conn->stm, key);

    if (state == SHOES_ERROR) {
        close_shoes_connection(conn);
    }
}

static void shoesConnectionWrite(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    const enum shoes_state state = stm_handler_write(&conn->stm, key);

    if (state == SHOES_ERROR) {
        close_shoes_connection(conn);
    }
}

static void shoesConnectionClose(struct selector_key *key) {
    shoes_connection *conn = (shoes_connection *) key->data;
    stm_handler_close(&conn->stm, key);
}

static const struct fd_handler shoesConnectionFdHandler = {
    .handle_read = shoesConnectionRead,
    .handle_write = shoesConnectionWrite,
    .handle_close = shoesConnectionClose,
};


const struct fd_handler *get_connection_fd_handler() {
    return &connectionFdHandler;
}

static void passive_socket_handler(struct selector_key *key)
{
    int fd = key->fd;

    socks5_connection * conn = malloc(sizeof(struct socks5_connection));
    if (conn == NULL) {
        perror("malloc error");
        return;
    }

    // Inicializo el struct
    memset(conn, 0x00, sizeof(*conn));
    buffer_init(&conn->read_buffer, BUFFER_DEFAULT_SIZE, conn->raw_buffer_a);
    buffer_init(&conn->write_buffer, BUFFER_DEFAULT_SIZE, conn->raw_buffer_b);

    conn->stm.initial = CONNECTION_READ;
    conn->stm.max_state = DONE;
    conn->stm.states = get_socks5_states();

    stm_init(&conn->stm);

    conn->client_interests = OP_READ;
    conn->origin_interests = OP_NOOP;

    conn->client_addr_len = sizeof(conn->client_addr);
    conn->client_socket = accept(fd, (struct sockaddr*)&conn->client_addr, &conn->client_addr_len);
    if (conn->client_socket == -1)
    {
        perror("Couldn't connect to client");
        close_connection(conn);
        return;
    }
    selector_fd_set_nio(conn->client_socket);

    if (selector_register(selector, conn->client_socket, &connectionFdHandler, OP_READ, conn)) {
        perror("selector_register error");
        close_connection(conn);
        return;
    }

    report_new_connection();
    printf("NEW CONNECTION\n");
}

static void shoes_passive_socket_handler(struct selector_key *key) {
    int fd = key->fd;

    shoes_connection * conn = malloc(sizeof(struct shoes_connection));
    if (conn == NULL) {
        perror("malloc error");
        return;
    }

    memset(conn, 0, sizeof(shoes_connection));
    buffer_init(&conn->read_buffer, SHOES_BUFFER_DEFAULT_SIZE, conn->raw_buffer_a);
    buffer_init(&conn->write_buffer, SHOES_BUFFER_DEFAULT_SIZE, conn->raw_buffer_b);

    conn->stm.initial = SHOES_AUTHENTICATION_READ;
    conn->stm.max_state = SHOES_ERROR;
    conn->stm.states = get_shoes_states();

    stm_init(&conn->stm);

    conn->client_interests = OP_READ;

    conn->client_socket = accept(fd, (struct sockaddr*)&conn->client_addr, &(socklen_t){sizeof(struct sockaddr_in)});
    if (conn->client_socket == -1)
    {
        perror("Couldn't connect to client");
        close_shoes_connection(conn);
        return;
    }
    selector_fd_set_nio(conn->client_socket);

    if (selector_register(selector, conn->client_socket, &shoesConnectionFdHandler, OP_READ, conn)) {
        perror("selector_register error");
        close_shoes_connection(conn);
        return;
    }

    printf("NEW CONNECTION\n");

}

const struct fd_handler passiveSocketFdHandler = {passive_socket_handler, 0, 0, 0};
const struct fd_handler shoesPassiveSocketHandler = {shoes_passive_socket_handler, 0, 0, 0};

static char *error_msg;

static int create_socket(char *port, char *addr, const struct fd_handler *selector_handler) {
    struct addrinfo hint, *res = NULL;
    int ret, fd;
    bool error = false;

    memset(&hint, 0, sizeof(hint));

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    ret = getaddrinfo(addr, port, &hint, &res);
    if (ret) {
        fprintf(stderr,"unable to get address info: %s", gai_strerror(ret));
        error = true;
        goto finally;
    }

    fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd == -1) {
        error_msg = "unable to create socket";
        error = true;
        goto finally;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
        error_msg = "unable to set socket options";
        error = true;
        goto finally;
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        error_msg = "bind client socket error";
        error = true;
        goto finally;
    }

    if (listen(fd, 1) < 0) {
        error_msg = "listen client socket error";
        error = true;
        goto finally;
    }

    int registerRet;
    if((registerRet = selector_register(selector, fd, selector_handler, OP_READ, NULL)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Passive socket register error: %s", selector_error(registerRet));
        error = true;
        goto finally;
    }

finally:
    if (error && fd != -1) {
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    return fd;
}

int network_handler(char *socks_addr, char *socks_port, char *shoes_addr, char *shoes_port)
{
    error_msg = NULL;
    int fd_socks = -1, fd_shoes = -1;
    // extra fds in case we need to create ipv4 and ipv6 sockets
    int fd_socks2 = -1, fd_shoes2 = -1;
    int ret = 0;

    signal(SIGCHLD, networkSelectorSignalHandler);

    struct timespec select_timeout = {0};
    select_timeout.tv_sec = SELECTOR_TIMEOUT;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    int selector_init_ret;
    if ((selector_init_ret = selector_init(&select_init_struct)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Selector init error: %s", selector_error(selector_init_ret));
        goto finally;
    }

    selector = selector_new(20);
    if (selector == NULL) {
        error_msg = "No se pudo instanciar el selector.";
        goto finally;
    }

    if (socks_addr == NULL) {
        if ((fd_socks = create_socket(socks_port, DEFAULT_SOCKS_ADDR_IPV4, &passiveSocketFdHandler)) == -1) {
            goto finally;
        }
        if ((fd_socks2 = create_socket(socks_port, DEFAULT_SOCKS_ADDR_IPV6, &passiveSocketFdHandler)) == -1) {
            goto finally;
        }
    } else {
        if ((fd_socks = create_socket(socks_port, socks_addr, &passiveSocketFdHandler)) == -1) {
            goto finally;
        }
    }

    if (shoes_addr == NULL) {
        if ((fd_shoes = create_socket(shoes_port, DEFAULT_SHOES_ADDR_IPV4, &shoesPassiveSocketHandler)) == -1) {
            goto finally;
        }
        if ((fd_shoes2 = create_socket(shoes_port, DEFAULT_SHOES_ADDR_IPV6, &shoesPassiveSocketHandler)) == -1) {
            goto finally;
        }
    } else {
        if ((fd_shoes = create_socket(shoes_port, shoes_addr, &shoesPassiveSocketHandler)) == -1) {
            goto finally;
        }
    }

    while (1) {
        int selectorStatus = selector_select(selector);
        if(selectorStatus != SELECTOR_SUCCESS) {
            fprintf(stderr, "Selector Select Error: %s", selector_error(selectorStatus));
            goto finally;
        }
    }

finally:
    if (error_msg)
    {
        perror(error_msg);
        ret = -1;
    }

    if (fd_socks != -1)
        close(fd_socks);
    if (fd_socks2 != -1)
        close(fd_socks2);
    if (fd_shoes != -1)
        close(fd_shoes);
    if (fd_shoes2 != -1)
        close(fd_shoes2);

    selector_destroy(selector);

    return ret;
}

void network_handler_cleanup()
{
    //close_connection(); TODO: Hacer close para todas las del selector
    selector_close();
}