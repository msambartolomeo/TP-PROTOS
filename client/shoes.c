#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shoes.h"

#define SHOES_VER 1

typedef struct shoesConnection {
    bool initialized;
    int fd;
} shoesConnection;

static shoesConnection conn = {0};

static shoesResponseStatus lastStatus;
static shoesPutCommand lastCommand;
static shoesConnectStatus connectStatus;

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
        connectStatus = CONNECT_SERV_FAIL;
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
        connectStatus = CONNECT_SERV_FAIL;
        return connectStatus; // TODO
    }

    // Wait full response
    if ((recv(conn.fd, buf, RES_LEN, MSG_WAITALL)) < RES_LEN) {
        perror("Handshake recv error");
        connectStatus = CONNECT_SERV_FAIL;
        return connectStatus; // TODO
    }

    uint8_t serv_ver = (uint8_t)buf[0];
    uint8_t serv_ret = (uint8_t)buf[1];

    if (*(uint8_t*)buf != SHOES_VER) {
        fprintf(stderr, "Invalid server shoes version: %d\n", serv_ver);
        connectStatus = CONNECT_SERV_FAIL;
        return connectStatus;
    }

    if(serv_ret == CONNECT_SUCCESS) {
        conn.initialized = true;
    }

    connectStatus = serv_ret;
    return serv_ret;
}

static int sendRequest(shoesFamily fmly, uint8_t cmd, void* data,
                       size_t dataLen) {
    size_t bufLen = dataLen + 2;
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
    const int RES_LEN = 16;

    if (sendGetRequest(CMD_METRICS) == -1) {
        fprintf(stderr, "Metrics request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = getResponseStatus()) != RESPONSE_SUCCESS) {
        lastStatus = status;
        return status;
    }

    uint8_t buf[RES_LEN];
    if (recv(conn.fd, buf, RES_LEN, MSG_WAITALL) < RES_LEN) {
        perror("Metrics recv error");
        return -1; // TODO
    }

    metrics->historicConnections = *(uint32_t*)&buf[0];
    metrics->currentConnections = *(uint32_t*)&buf[4];
    metrics->bytesTransferred = *(uint64_t*)&buf[8];

    lastStatus = status;
    return status;
}

shoesResponseStatus shoesGetUserList(shoesUserList* list) {
    if (sendGetRequest(CMD_LIST_USERS) == -1) {
        fprintf(stderr, "Metrics request error\n");
        return -1; // TODO
    }

    uint8_t status;
    if ((status = getResponseStatus()) != RESPONSE_SUCCESS) {
        lastStatus = status;
        return status;
    }

    if (recv(conn.fd, &list->uCount, 1, MSG_WAITALL) < 1) {
        perror("User count recv error");
        return -1; // TODO
    }

    uint8_t uLen;
    list->users = malloc(list->uCount * sizeof(char *));
    for (uint8_t i = 0; i < list->uCount ; i++) {
        if (recv(conn.fd, &uLen, 1, MSG_WAITALL) < 1) {
            perror("User len recv error");
            return -1; // TODO
        }
        list->users[i] = malloc(uLen + 1);
        list->users[i][uLen] = '\0';
        if (recv(conn.fd, list->users[i], uLen, MSG_WAITALL) < uLen) {
            perror("User name recv error");
            return -1; // TODO
        }
    }

    lastStatus = status;
    return status;
}

shoesResponseStatus shoesGetSpoofingStatus(bool* status) {
    if (sendGetRequest(CMD_GET_SPOOF) == -1) {
        fprintf(stderr, "Spoofing request error\n");
        return -1; // TODO
    }

    uint8_t res_status;
    if ((res_status = getResponseStatus()) != RESPONSE_SUCCESS) {
        lastStatus = res_status;
        return res_status;
    }

    uint8_t res;
    if (recv(conn.fd, &res, 1, MSG_WAITALL) < 1) {
        perror("Spoofing get recv error");
        return -1; // TODO
    }

    *status = (bool)res;

    lastStatus = res_status;
    return res_status;
}

static inline shoesResponseStatus shoesAddOrEditUser(const shoesUser* user,
                                                     shoesPutCommand cmd) {
    size_t ulen = strlen(user->name);
    size_t plen = strlen(user->pass);

    if(ulen > UINT8_MAX || plen > UINT8_MAX) {
        //ESTO NO DEBERIA PASAR NUNCA
        return -1;
    }

    size_t dataLen = ulen + plen + 2;
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
    lastCommand = CMD_ADD_USER;
    lastStatus = shoesAddOrEditUser(user, CMD_ADD_USER);
    return lastStatus;
}

shoesResponseStatus shoesEditUser(const shoesUser* user) {
    lastCommand = CMD_EDIT_USER;
    lastStatus = shoesAddOrEditUser(user, CMD_EDIT_USER);
    return lastStatus;
}

shoesResponseStatus shoesRemoveUser(const char* user) {
    lastCommand = CMD_REMOVE_USER;

    size_t ulen = strlen(user);
    size_t dataLen = ulen + 1;
    uint8_t data[dataLen];

    data[0] = (uint8_t)ulen;
    memcpy(&data[1], user, ulen);

    if (sendPutRequest(CMD_REMOVE_USER, data, dataLen) == -1) {
        fprintf(stderr, "Remove user request error\n");
        return -1;
    }

    lastStatus = getResponseStatus();
    return lastStatus;
}

shoesResponseStatus shoesModifyBufferSize(uint16_t size) {
    lastCommand = CMD_MODIFY_BUFFER;

    if (sendPutRequest(CMD_MODIFY_BUFFER, &size, sizeof(uint16_t)) == -1) {
        fprintf(stderr, "Modify buffer request error\n");
        return -1;
    }

    lastStatus = getResponseStatus();
    return lastStatus;
}

shoesResponseStatus shoesModifyPasswordSpoofingStatus(bool newStatus) {
    lastCommand = CMD_MODIFY_SPOOF;

    if (sendPutRequest(CMD_MODIFY_SPOOF, &newStatus, sizeof(bool)) == -1) {
        fprintf(stderr, "Modify spoofing request error\n");
        return -1;
    }

    lastStatus = getResponseStatus();
    return lastStatus;
}

void freeShoesUser(shoesUser* user) {
    free(user->name);
    free(user->pass);
}

void freeShoesUserList(shoesUserList* list) {
    for (uint8_t i = 0; i < list->uCount; i++) {
        free(list->users[i]);
    }
    free(list->users);
}

void shoesCloseConnection() {
    if(conn.initialized) {
        close(conn.fd);
    }
}

const char* humanReadableConnectStatus(shoesConnectStatus status) {
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

static const char* humanReadableCmdError(shoesResponseStatus status, shoesPutCommand putCommand) {
    switch (putCommand) {
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

static const char* humanReadableResponseStatus(shoesResponseStatus status, shoesPutCommand putCommand) {
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
            return humanReadableCmdError(status, putCommand);
        default:
            return "Unknown error.";
    }
}

const char* shoesHumanReadableStatus() {
    if(!conn.initialized) {
        return humanReadableConnectStatus(connectStatus);
    }

    return humanReadableResponseStatus(lastStatus, lastCommand);
}


