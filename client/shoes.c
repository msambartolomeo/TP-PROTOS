#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "shoes.h"

#define SHOES_VER 1

typedef struct shoesConnection {
    bool initialized;
    int fd;
} shoesConnection;

static shoesConnection conn = {0};

static int serverConnection(const char* host, const char* port) {
    if (conn.initialized) {
        fprintf(stderr, "Error: Tried to connect to server more than once.\n");
        return -1;
    }
    conn.fd = -1;

    struct addrinfo* info;
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status;
    if ((status = getaddrinfo(host, port, &hints, &info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    for (struct addrinfo* p = info; p != NULL; p = p->ai_next) {
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

shoesConnectStatus shoesConnect(const char* host, const char* port,
                                const shoesUser* user) {
    const int REQ_MAXLEN = 513;
    const int RES_LEN = 2;

    if (serverConnection(host, port) == -1) {
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
    strncpy((char*)&buf[buflen], user->name, ulen);
    buflen += ulen;

    // PLEN
    uint8_t plen = strlen(user->pass);
    buf[buflen] = plen;
    buflen += sizeof(uint8_t);

    // PASSWD
    strncpy((char*)&buf[buflen], user->pass, plen);
    buflen += plen;

    if (send(conn.fd, buf, buflen, 0) == -1) {
        perror("Handshake send error");
        return CONNECT_SERV_FAIL; // TODO
    }

    // Wait full response
    if ((recv(conn.fd, buf, RES_LEN, MSG_WAITALL)) < RES_LEN) {
        perror("Handshake recv error");
        return CONNECT_SERV_FAIL; // TODO
    }

    uint8_t serv_ver = (uint8_t)buf[0];
    uint8_t serv_ret = (uint8_t)buf[1];

    if (*(uint8_t*)buf != SHOES_VER) {
        fprintf(stderr, "Invalid server shoes version: %d\n", serv_ver);
        return CONNECT_SERV_FAIL;
    }

    return serv_ret;
}

static int sendRequest(shoesFamily fmly, uint8_t cmd, void* data,
                       size_t dataLen) {
    uint8_t bufLen = dataLen + 2;
    uint8_t buf[bufLen];

    buf[0] = (uint8_t)fmly;
    buf[1] = (uint8_t)cmd;
    memcpy(&buf[2], data, dataLen);

    if (send(conn.fd, buf, bufLen, 0) == -1) {
        perror("Request send error");
        return -1; // TODO
    }

    return 0;
}

static inline int sendGetRequest(uint8_t cmd) {
    return sendRequest(SHOES_GET, cmd, NULL, 0);
}

static inline int sendPutRequest(uint8_t cmd, void* data, size_t dataLen) {
    return sendRequest(SHOES_PUT, cmd, data, dataLen);
}

static uint8_t getResponseStatus() {
    uint8_t res_status = -1;

    if (recv(conn.fd, &res_status, 1, MSG_WAITALL) != 1) {
        return -1; // TODO
    }

    return res_status;
}

shoesResponseStatus shoesGetMetrics(shoesServerMetrics* metrics) {
    const int RES_LEN = 13;

    if (sendGetRequest(CMD_METRICS) == -1) {
        fprintf(stderr, "Metrics request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = getResponseStatus()) != RESPONSE_SUCCESS) {
        return status;
    }

    uint8_t buf[RES_LEN];
    if (recv(conn.fd, buf, RES_LEN - 1, MSG_WAITALL) < RES_LEN) {
        perror("Metrics recv error");
        return -1; // TODO
    }

    metrics->historicConnections = *(uint32_t*)&buf[1];
    metrics->currentConnections = *(uint32_t*)&buf[5];
    metrics->bytesTransferred = *(uint32_t*)&buf[9];

    return status;
}

shoesResponseStatus shoesGetUserList(shoesUserList* list) {
    if (sendGetRequest(CMD_LIST_USERS) == -1) {
        fprintf(stderr, "Metrics request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = getResponseStatus()) != RESPONSE_SUCCESS) {
        return status;
    }

    uint16_t ulen;
    if (recv(conn.fd, &ulen, sizeof(uint16_t), MSG_WAITALL) !=
        sizeof(uint16_t)) {
        perror("Userlist recv error");
        return -1; // TODO
    }

    char* usersBuf = malloc(ulen);
    if (usersBuf == NULL) {
        fprintf(stderr, "Out of memory.\n");
        return -1; // TODO
    }

    if (recv(conn.fd, usersBuf, ulen, MSG_WAITALL) < ulen) {
        perror("Userlist recv error");
        return -1; // TODO
    }

    list->users = malloc(ulen * sizeof(char**));
    if (list->users == NULL) {
        fprintf(stderr, "Out of memory.\n");
        return -1; // TODO
    }

    list->n = 0;
    for (int i = 0; i < ulen; i++) {
        if (i == 0 || usersBuf[i - 1] == 0)
            list->users[list->n++] = &usersBuf[i];
    }

    list->users = realloc(list->users, list->n * sizeof(char**));

    return status;
}

shoesResponseStatus shoesGetSpoofingStatus(bool* status) {
    if (sendGetRequest(CMD_LIST_USERS) == -1) {
        fprintf(stderr, "Spoofing request error\n");
        return -1; // TODO
    }

    uint8_t res_status;
    if ((res_status = getResponseStatus()) != RESPONSE_SUCCESS) {
        return res_status;
    }

    uint8_t res;
    if (recv(conn.fd, &res, 1, MSG_WAITALL) < 1) {
        perror("Spoofing get recv error");
        return -1; // TODO
    }

    *status = (bool)res;

    return res_status;
}

static inline shoesResponseStatus shoesAddOrEditUser(const shoesUser* user,
                                                     shoesPutCommand cmd) {
    size_t ulen = strlen(user->name);
    size_t plen = strlen(user->pass);
    uint8_t dataLen = ulen + plen + 2;
    uint8_t data[dataLen];

    data[0] = (uint8_t)ulen;
    memcpy(&data[1], user->name, ulen);

    data[1 + ulen] = (uint8_t)plen;
    memcpy(&data[2 + ulen], user->pass, plen);

    if (sendPutRequest(cmd, data, dataLen) == -1) {
        fprintf(stderr, "Add user request error\n");
        return -1;
    }

    return getResponseStatus();
}

shoesResponseStatus shoesAddUser(const shoesUser* user) {
    return shoesAddOrEditUser(user, CMD_ADD_USER);
}

shoesResponseStatus shoesEditUser(const shoesUser* user) {
    return shoesAddOrEditUser(user, CMD_EDIT_USER);
}

shoesResponseStatus shoesRemoveUser(const char* user) {
    size_t ulen = strlen(user);
    size_t dataLen = ulen + 1;
    uint8_t data[dataLen];

    data[0] = (uint8_t)ulen;
    memcpy(&data[1], user, ulen);

    if (sendPutRequest(CMD_REMOVE_USER, data, dataLen) == -1) {
        fprintf(stderr, "Remove user request error\n");
        return -1;
    }

    return getResponseStatus();
}

shoesResponseStatus shoesModifyBufferSize(uint16_t size) {
    if (sendPutRequest(CMD_MODIFY_BUFFER, &size, sizeof(uint16_t)) == -1) {
        fprintf(stderr, "Modify buffer request error\n");
        return -1;
    }

    return getResponseStatus();
}

shoesResponseStatus shoesModifyPasswordSpoofingStatus(bool newStatus) {
    if (sendPutRequest(CMD_MODIFY_SPOOF, &newStatus, sizeof(bool)) == -1) {
        fprintf(stderr, "Modify spoofing request error\n");
        return -1;
    }

    return getResponseStatus();
}

void freeShoesUser(shoesUser* user) {
    free(user->name);
    free(user->pass);
}

void freeShoesUserList(shoesUserList* list) {
    free(list->users[0]);
    free(list->users);
}
