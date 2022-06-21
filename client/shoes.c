#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shoes.h"

#define SHOES_VER 1

typedef struct shoes_connection {
    bool initialized;
    int fd;
} shoes_connection;

static shoes_connection conn = {0};

static shoes_response_status last_status;
static shoes_put_command last_command;
static shoes_connect_status connect_status;

static int server_connection(const char * host, const char * port) {
    if (conn.initialized) {
        fprintf(stderr, "Error: Tried to connect to server more than once.\n");
        return -1;
    }
    conn.fd = -1;

    struct addrinfo * info;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status;
    if ((status = getaddrinfo(host, port, &hints, &info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    for (struct addrinfo * p = info; p != NULL; p = p->ai_next) {
        int sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, p->ai_addr, p->ai_addrlen) != 0)
            continue;

        conn.fd = sock;
        break;
    }
    freeaddrinfo(info);

    if (conn.fd == -1) {
        fprintf(stderr, "Couldn't connect to server.\n");
        return -1;
    }

    return 0;
}

shoes_connect_status shoes_connect(const char * host, const char * port,
                                   const shoes_user * user) {
    const int REQ_MAXLEN = 513;
    const int RES_LEN = 2;

    if (server_connection(host, port) == -1) {
        connect_status = CONNECT_SERV_FAIL;
        return CONNECT_SERV_FAIL; // TODO: return proper error code
    }

    size_t buflen = 0;
    uint8_t buf[REQ_MAXLEN];

    // VERSION
    buf[buflen] = SHOES_VER;
    buflen += sizeof(uint8_t);

    // ULEN
    uint8_t ulen = strlen(user->name);
    buf[buflen] = ulen;
    buflen += sizeof(uint8_t);

    // UNAME
    strncpy((char *)&buf[buflen], user->name, ulen);
    buflen += ulen;

    // PLEN
    uint8_t plen = strlen(user->pass);
    buf[buflen] = plen;
    buflen += sizeof(uint8_t);

    // PASSWD
    strncpy((char *)&buf[buflen], user->pass, plen);
    buflen += plen;

    if (send(conn.fd, buf, buflen, 0) == -1) {
        perror("Handshake send error");
        connect_status = CONNECT_SERV_FAIL;
        return connect_status; // TODO
    }

    // Wait full response
    if ((recv(conn.fd, buf, RES_LEN, MSG_WAITALL)) < RES_LEN) {
        perror("Handshake recv error");
        connect_status = CONNECT_SERV_FAIL;
        return connect_status; // TODO
    }

    uint8_t serv_ver = (uint8_t)buf[0];
    uint8_t serv_ret = (uint8_t)buf[1];

    if (*(uint8_t *)buf != SHOES_VER) {
        fprintf(stderr, "Invalid server shoes version: %d\n", serv_ver);
        connect_status = CONNECT_SERV_FAIL;
        return connect_status;
    }

    if (serv_ret == CONNECT_SUCCESS) {
        conn.initialized = true;
    }

    connect_status = serv_ret;
    return serv_ret;
}

static int send_request(shoes_family fmly, uint8_t cmd, void * data,
                        size_t data_len) {
    size_t buf_len = data_len + 2;
    uint8_t buf[buf_len];

    buf[0] = (uint8_t)fmly;
    buf[1] = (uint8_t)cmd;
    memcpy(&buf[2], data, data_len);

    if (send(conn.fd, buf, buf_len, 0) == -1) {
        perror("Request send error");
        return -1; // TODO
    }

    return 0;
}

static inline int send_get_request(uint8_t cmd) {
    return send_request(SHOES_GET, cmd, NULL, 0);
}

static inline int send_put_request(uint8_t cmd, void * data, size_t data_len) {
    return send_request(SHOES_PUT, cmd, data, data_len);
}

static uint8_t get_response_status() {
    uint8_t res_status = -1;

    if (recv(conn.fd, &res_status, 1, MSG_WAITALL) != 1) {
        return -1; // TODO
    }

    return res_status;
}

shoes_response_status shoes_get_metrics(shoes_server_metrics * metrics) {
    const int RES_LEN = 16;

    if (send_get_request(CMD_METRICS) == -1) {
        fprintf(stderr, "Metrics request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = get_response_status()) != RESPONSE_SUCCESS) {
        last_status = status;
        return status;
    }

    uint8_t buf[RES_LEN];
    if (recv(conn.fd, buf, RES_LEN, MSG_WAITALL) < RES_LEN) {
        perror("Metrics recv error");
        return -1; // TODO
    }

    metrics->historic_connections = *(uint32_t *)&buf[0];
    metrics->current_connections = *(uint32_t *)&buf[4];
    metrics->bytes_transferred = *(uint64_t *)&buf[8];

    last_status = status;
    return status;
}

shoes_response_status shoes_get_user_list(shoes_user_list * list) {
    if (send_get_request(CMD_LIST_USERS) == -1) {
        fprintf(stderr, "List users request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = get_response_status()) != RESPONSE_SUCCESS) {
        last_status = status;
        return status;
    }

    if (recv(conn.fd, &list->u_count, 1, MSG_WAITALL) < 1) {
        perror("User count recv error");
        return -1; // TODO
    }

    uint8_t ulen;
    list->users = malloc(list->u_count * sizeof(char *));
    for (uint8_t i = 0; i < list->u_count; i++) {
        if (recv(conn.fd, &ulen, 1, MSG_WAITALL) < 1) {
            perror("User len recv error");
            return -1; // TODO
        }
        list->users[i] = malloc(ulen + 1);
        list->users[i][ulen] = '\0';
        if (recv(conn.fd, list->users[i], ulen, MSG_WAITALL) < ulen) {
            perror("User name recv error");
            return -1; // TODO
        }
    }

    last_status = status;
    return status;
}

shoes_response_status shoes_get_spoofing_status(bool * status) {
    if (send_get_request(CMD_GET_SPOOF) == -1) {
        fprintf(stderr, "Spoofing request error\n");
        return -1; // TODO
    }

    uint8_t res_status;
    if ((res_status = get_response_status()) != RESPONSE_SUCCESS) {
        last_status = res_status;
        return res_status;
    }

    uint8_t res;
    if (recv(conn.fd, &res, 1, MSG_WAITALL) < 1) {
        perror("Spoofing get recv error");
        return -1; // TODO
    }

    *status = (bool)res;

    last_status = res_status;
    return res_status;
}

static inline shoes_response_status
shoes_add_or_edit_user(const shoes_user * user, shoes_put_command cmd) {
    size_t ulen = strlen(user->name);
    size_t plen = strlen(user->pass);

    if (ulen > UINT8_MAX || plen > UINT8_MAX) {
        // ESTO NO DEBERIA PASAR NUNCA
        return -1;
    }

    size_t data_len = ulen + plen + 2;
    uint8_t data[data_len];

    data[0] = (uint8_t)ulen;
    memcpy(&data[1], user->name, ulen);

    data[1 + ulen] = (uint8_t)plen;
    memcpy(&data[2 + ulen], user->pass, plen);

    if (send_put_request(cmd, data, data_len) == -1) {
        fprintf(stderr, "Add user request error\n");
        return -1;
    }

    return get_response_status();
}

shoes_response_status shoes_add_user(const shoes_user * user) {
    last_command = CMD_ADD_USER;
    last_status = shoes_add_or_edit_user(user, CMD_ADD_USER);
    return last_status;
}

shoes_response_status shoes_edit_user(const shoes_user * user) {
    last_command = CMD_EDIT_USER;
    last_status = shoes_add_or_edit_user(user, CMD_EDIT_USER);
    return last_status;
}

shoes_response_status shoes_remove_user(const char * user) {
    last_command = CMD_REMOVE_USER;

    size_t ulen = strlen(user);
    size_t data_len = ulen + 1;
    uint8_t data[data_len];

    data[0] = (uint8_t)ulen;
    memcpy(&data[1], user, ulen);

    if (send_put_request(CMD_REMOVE_USER, data, data_len) == -1) {
        fprintf(stderr, "Remove user request error\n");
        return -1;
    }

    last_status = get_response_status();
    return last_status;
}

shoes_response_status shoes_modify_buffer_size(uint16_t size) {
    last_command = CMD_MODIFY_BUFFER;

    if (send_put_request(CMD_MODIFY_BUFFER, &size, sizeof(uint16_t)) == -1) {
        fprintf(stderr, "Modify buffer request error\n");
        return -1;
    }

    last_status = get_response_status();
    return last_status;
}

shoes_response_status shoes_modify_password_spoofing_status(bool new_status) {
    last_command = CMD_MODIFY_SPOOF;

    if (send_put_request(CMD_MODIFY_SPOOF, &new_status, sizeof(bool)) == -1) {
        fprintf(stderr, "Modify spoofing request error\n");
        return -1;
    }

    last_status = get_response_status();
    return last_status;
}

void free_shoes_user(shoes_user * user) {
    free(user->name);
    free(user->pass);
}

void free_shoes_user_list(shoes_user_list * list) {
    for (uint8_t i = 0; i < list->u_count; i++) {
        free(list->users[i]);
    }
    free(list->users);
}

void shoes_close_connection() {
    if (conn.initialized) {
        close(conn.fd);
    }
}

const char * human_readable_connect_status(shoes_connect_status status) {
    switch (status) {
    case CONNECT_SUCCESS:
        return "Success";
    case CONNECT_SERV_FAIL:
        return "Internal server error";
    case CONNECT_INVALID_VER:
        return "Invalid SHOES Version";
    case CONNNECT_INVALID_USER:
        return "Invalid username or password";
    default:
        return "Unknown error";
    }
}

static const char * human_readable_cmd_error(shoes_response_status status,
                                             shoes_put_command put_command) {
    switch (put_command) {
    case CMD_ADD_USER:
        switch (status) {
        case RESPONSE_CMD_FAIL_04:
            return "User already exists";
        case RESPONSE_CMD_FAIL_05:
            return "Maximum number of users reached";
        default:
            return "Unknown error";
        }
    case CMD_REMOVE_USER:
    case CMD_EDIT_USER:
        return "The user does not exist";
    case CMD_MODIFY_BUFFER:
        return "Buffer size out of range";
    case CMD_MODIFY_SPOOF:
        return "Invalid spoofing status";
    default:
        return "Unknown error";
    }
}

static const char *
human_readable_response_status(shoes_response_status status,
                               shoes_put_command put_command) {
    switch (status) {
    case RESPONSE_SUCCESS:
        return "Success";
    case RESPONSE_SERV_FAIL:
        return "Internal server error";
    case RESPONSE_FMLY_NOT_SUPPORTED:
        return "Family not supported";
    case RESPONSE_CMD_NOT_SUPPORTED:
        return "Command not supported";
    case RESPONSE_CMD_FAIL_04:
    case RESPONSE_CMD_FAIL_05:
        return human_readable_cmd_error(status, put_command);
    default:
        return "Unknown error.";
    }
}

const char * shoes_human_readable_status() {
    if (!conn.initialized) {
        return human_readable_connect_status(connect_status);
    }

    return human_readable_response_status(last_status, last_command);
}
