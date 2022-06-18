#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct shoesUser {
    char* name;
    char* pass;
} shoesUser;

typedef enum shoesFamily { SHOES_GET = 0, SHOES_PUT } shoesFamily;

typedef enum shoesPutCommand {
    CMD_ADD_USER = 0,
    CMD_REMOVE_USER,
    CMD_EDIT_USER,
    CMD_MODIFY_BUFFER,
    CMD_MODIFY_SPOOF,
} shoesPutCommand;

typedef enum shoesGetCommand {
    CMD_METRICS = 0,
    CMD_LIST_USERS,
    CMD_GET_SPOOF,
} shoesGetCommand;

typedef enum shoesConnectStatus {
    CONNECT_SUCCESS = 0,
    CONNECT_SERV_FAIL,
    CONNECT_INVALID_VER,
    CONNNECT_INVALID_USER
} shoesConnectStatus;

shoesConnectStatus shoesConnect(const char* host, const char* port,
                                const shoesUser* user);

typedef enum shoesResponseStatus {
    RESPONSE_SUCCESS = 0,
    RESPONSE_SERV_FAIL,
    RESPONSE_FMLY_NOT_SUPPORTED,
    RESPONSE_CMD_NOT_SUPPORTED,
    RESPONSE_CMD_FAIL
} shoesResponseStatus;

typedef struct shoesServerMetrics {
    uint32_t historicConnections;
    uint32_t currentConnections;
    uint32_t bytesTransferred;
} shoesServerMetrics;
shoesResponseStatus shoesGetMetrics(shoesServerMetrics* metrics);

typedef struct shoesUserList {
    uint32_t n;
    char** users;
} shoesUserList;
shoesResponseStatus shoesGetUserList(shoesUserList* list);

shoesResponseStatus shoesGetSpoofingStatus(bool* status);

shoesResponseStatus shoesAddUser(const shoesUser* user);
shoesResponseStatus shoesRemoveUser(const char* user);
shoesResponseStatus shoesEditUser(const shoesUser* user);

shoesResponseStatus shoesModifyBufferSize(uint16_t size);
shoesResponseStatus shoesModifyPasswordSpoofingStatus(bool status);

void freeShoesUser(shoesUser* user);
void freeShoesUserList(shoesUserList* list);
