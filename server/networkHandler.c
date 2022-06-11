#include <arpa/inet.h>
#include <buffer.h>
#include <errno.h>
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

#define DEFAULT_CLIENT_PORT 1080
#define DEFAULT_SERVER_PORT 80
#define SELECTOR_TIMEOUT 100

static fd_selector selector;

static void networkSelectorSignalHandler()
{
    printf("SIGCHLD SIGNAL");
}

void close_connection(socks5_connection * connection)
{
    int client_socket = connection->client_socket;
    int server_socket = connection->server_socket;

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

    printf("CONNECTION CLOSED\n");
}
// TODO check if buffers are correct
static void server_socket_read_handler(struct selector_key *key)
{
    socks5_connection * conn = (socks5_connection *)key->data;

    if(!buffer_can_write(&conn->read_buffer)){
        conn->client_interests &= ~OP_READ; // Con máquina de estados esto seguramente lo borremos
        selector_set_interest(selector, conn->server_socket, conn->server_interests);
        return;
    }

    size_t wbytes;
    uint8_t *bufptr = buffer_write_ptr(&conn->read_buffer, &wbytes);

    ssize_t len = recv(conn->server_socket, bufptr, wbytes, MSG_DONTWAIT);

    if (len <= 0)
    {
        if (len == -1 && errno != EWOULDBLOCK)
            perror("SERVER READ ERROR");

        close_connection(conn);

        return;
    }
    else
    {
        write(STDOUT_FILENO, bufptr, len);
        printf("\n\n");

        buffer_write_adv(&conn->read_buffer, len);

        conn->client_interests |= OP_WRITE;
        selector_set_interest(selector, conn->client_socket, conn->client_interests);
    }
}

static void server_socket_write_handler(struct selector_key *key)
{
    socks5_connection * conn = (socks5_connection *)key->data;

    int error = 0;
    getsockopt(conn->server_socket, SOL_SOCKET, SO_ERROR, &error, &(socklen_t){sizeof(int)});
    if(error) {
        perror("SERVER CONNECTION ERROR");
        close_connection(conn);
        return;
    }

    if(!buffer_can_read(&conn->write_buffer)){
        conn->server_interests &= ~OP_WRITE;
        selector_set_interest(selector, conn->server_socket, conn->server_interests);
        return;
    }

    size_t rbytes;
    uint8_t *bufptr = buffer_read_ptr(&conn->write_buffer, &rbytes);

    ssize_t len = send(conn->server_socket, bufptr, rbytes, MSG_DONTWAIT);
    if (len == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            perror("SERVER WRITE FAILED");
            exit(1);
        }
    }
    else
    {
        buffer_read_adv(&conn->write_buffer, len);
        conn->server_interests |= OP_READ;
        selector_set_interest(selector, conn->server_socket, conn->server_interests);
    }
}

static void client_socket_read_handler(struct selector_key *key)
{
    socks5_connection * conn = (socks5_connection *) key->data;

    if(!buffer_can_write(&conn->write_buffer)){
        conn->client_interests &= ~OP_READ;
        selector_set_interest(selector, conn->client_socket, conn->client_interests);
        return;
    }

    size_t wbytes;
    uint8_t *bufptr = buffer_write_ptr(&conn->write_buffer, &wbytes);

    ssize_t len = recv(conn->client_socket, bufptr, wbytes, MSG_DONTWAIT);

    if (len <= 0)
    {
        if (len == -1) {
            perror("CLIENT READ ERROR");
        }
        close_connection(conn);
    }
    else
    {
        write(STDOUT_FILENO, bufptr, len);
        printf("\n\n");

        buffer_write_adv(&conn->write_buffer, len);

        conn->server_interests |= OP_WRITE;
        selector_set_interest(selector, conn->server_socket, conn->server_interests);
    }
}

static void client_socket_write_handler(struct selector_key *key)
{
    socks5_connection * conn = (socks5_connection *) key->data;

    if(!buffer_can_read(&conn->read_buffer)) {
        conn->client_interests &= ~OP_WRITE;
        selector_set_interest(selector, conn->client_socket, conn->client_interests);
        return;
    }

    size_t rbytes;
    uint8_t *bufptr = buffer_read_ptr(&conn->read_buffer, &rbytes);

    ssize_t len = send(conn->client_socket, bufptr, rbytes, MSG_DONTWAIT);
    if (len == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            perror("SERVER WRITE FAILED");
            close_connection(conn);
        }
    }
    else
    {
        buffer_read_adv(&conn->read_buffer, len);
        conn->server_interests |= OP_WRITE;
        selector_set_interest(selector, conn->server_socket, conn->server_interests);
    }
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

__attribute__((unused)) static const struct fd_handler selectorClientFdHandler = {client_socket_read_handler, client_socket_write_handler, 0, 0};
__attribute__((unused)) static const struct fd_handler selectorServerFdHandler = {server_socket_read_handler, server_socket_write_handler, 0, 0};

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
    conn->server_interests = OP_NOOP;

    conn->client_socket = accept(fd, (struct sockaddr*)&conn->client_addr, &(socklen_t){sizeof(struct sockaddr_in)});
    if (conn->client_socket == -1)
    {
        perror("Couldn't connect to client");
        close_connection(conn);
        return;
    }
    selector_fd_set_nio(conn->client_socket);

    // TODO: to be replaced with socks5
//    conn->server_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
//    if (conn->server_socket == -1)
//    {
//        perror("unable to create socket");
//        close_connection(conn);
//        return;
//    }
//
//    struct sockaddr_in serveraddr = {0};
//    serveraddr.sin_family = AF_INET;
//    serveraddr.sin_port = htons(DEFAULT_SERVER_PORT);
//
//    if (inet_pton(AF_INET, "127.0.0.1", &serveraddr.sin_addr) <= 0)
//    {
//        perror("inet_aton error");
//        close_connection(conn);
//        return;
//    }
//
//    if (connect(conn->server_socket, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in)) < 0)
//    {
//        if(errno != EINPROGRESS) {
//            perror("SERVER CONNECTION ERROR");
//            close_connection(conn);
//            return;
//        }
//    }

    if (selector_register(selector, conn->client_socket, &connectionFdHandler, OP_READ, conn)) {
        perror("selector_register error");
        close_connection(conn);
        return;
    }

    printf("NEW CONNECTION\n");
}

const struct fd_handler passiveSocketFdHandler = {passive_socket_handler, 0, 0, 0};

int network_handler()
{
    char *error_msg = NULL;

    signal(SIGCHLD, networkSelectorSignalHandler);

    struct timespec select_timeout = {0};
    select_timeout.tv_sec = SELECTOR_TIMEOUT;
    struct selector_init select_init_struct = {SIGCHLD, select_timeout};

    int selector_init_ret;
    if ((selector_init_ret = selector_init(&select_init_struct)) != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "Selector init error: %s", selector_error(selector_init_ret));
        goto error;
    }

    selector = selector_new(20);
    if (selector == NULL)
    {
        error_msg = "No se pudo instanciar el selector.";
        goto error;
    }

    const int passiveSocket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (!(passiveSocket))
    {
        error_msg = "unable to create socket";
        goto error;
    }

    setsockopt(passiveSocket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in passiveaddr = {0};
    passiveaddr.sin_addr.s_addr = INADDR_ANY;
    passiveaddr.sin_family = AF_INET;
    passiveaddr.sin_port = htons(DEFAULT_CLIENT_PORT);
    if (bind(passiveSocket, (struct sockaddr *)&passiveaddr, sizeof(passiveaddr)) < 0)
    {
        error_msg = "bind client socket error";
        goto error;
    }

    if (listen(passiveSocket, 1) < 0)
    {
        error_msg = "listen client socket error";
        goto error;
    }

    int registerRet;
    if((registerRet = selector_register(selector, passiveSocket, &passiveSocketFdHandler, OP_READ, NULL)) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Passive socket register error: %s", selector_error(registerRet));
        exit(1);
    }

    while (1)
    {
        int selectorStatus = selector_select(selector);
        if(selectorStatus != SELECTOR_SUCCESS) {
            fprintf(stderr, "Selector Select Error: %s", selector_error(selectorStatus));
            exit(1);
        }
    }

error:
    if (error_msg)
    {
        perror(error_msg);
        return -1;
    }

    return 0;
}

void network_handler_cleanup()
{
    //close_connection(); TODO: Hacer close para todas las del selector
    selector_close();
}
