#pragma once

#include <stdint.h>
#include <stdlib.h>
#include "buffer.h"

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_MAX_LENGTH 256
#define BUFSIZE_MIN_LENGTH 512
#define BUFSIZE_MAX_LENGTH 65535

struct shoesMetrics {
    uint32_t historic_connections;
    uint32_t concurrent_connections;
    uint32_t bytes_transferred;
};

enum shoesFamily {
    SHOES_GET = 0x00,
    SHOES_PUT = 0x01,
};

enum shoesGetCommands {
    CMD_METRICS = 0x00,
    CMD_LIST_USERS = 0x01,
    CMD_SPOOFING_STATUS = 0x02,
};

enum shoesPutCommands {
    CMD_ADD_USER = 0x00,
    CMD_REMOVE_USER = 0x01,
    CMD_EDIT_USER = 0x02,
    CMD_MODIFY_BUFFER = 0x03,
    CMD_MODIFY_SPOOF = 0x04,
};

enum shoesParseState {
    PARSE_FMLY,
    PARSE_CMD,
    PARSE_DATA,
    PARSE_DONE,
    PARSE_ERROR_UNSUPPORTED_FMLY,
    PARSE_ERROR_UNSUPPORTED_CMD,
};

enum shoesPutAddEditUserState {
    PARSE_ADD_EDIT_USER_ULEN,
    PARSE_ADD_EDIT_USER_USER,
    PARSE_ADD_EDIT_USER_PLEN,
    PARSE_ADD_EDIT_USER_PASS
};

enum shoesPutRemoveUserState {
    PARSE_REMOVE_USER_ULEN,
    PARSE_REMOVE_USER_USER
};

enum shoesPutModifyBufferState {
    PARSE_BUFFER_SIZE,
    PARSE_BUFFER_DONE,
    PARSE_ERROR_BUFSIZE_OUT_OF_RANGE,
};

typedef struct shoesPutAddEditUserParser {
    enum shoesPutAddEditUserState state;
    uint8_t username[USERNAME_MAX_LENGTH];
    uint8_t password[PASSWORD_MAX_LENGTH];
    uint8_t remaining;
    uint8_t *pointer;
} shoesPutAddEditUserParser;

typedef struct shoesPutRemoveUserParser {
    enum shoesPutRemoveUserState state;
    uint8_t username[USERNAME_MAX_LENGTH];
    uint8_t remaining;
    uint8_t *pointer;
} shoesPutRemoveUserParser;

typedef struct shoesPutModifyBufferParser {
    enum shoesPutModifyBufferState state;
    uint16_t bufferSize;
    uint8_t remaining;
    uint8_t *pointer;
} shoesPutModifyBufferParser;

typedef enum shoesResponseStatus {
    RESPONSE_SUCCESS = 0x00,
    RESPONSE_SERV_FAIL = 0x01,
    RESPONSE_FMLY_NOT_SUPPORTED = 0x02,
    RESPONSE_CMD_NOT_SUPPORTED = 0x03,
    RESPONSE_CMD_FAIL_1 = 0x04,
    RESPONSE_CMD_FAIL_SECOND = 0x05
} shoesResponseStatus;

typedef struct shoesResponse {
    shoesResponseStatus status;
    uint8_t * data;
    size_t dataSize;
    size_t remaining;
} shoesResponse;

typedef struct shoesParser {
    enum shoesParseState state;
    enum shoesFamily family;
    union {
        enum shoesGetCommands get;
        enum shoesPutCommands put;
    } cmd;
    void (*parse)(struct shoesParser *parser, uint8_t byte);
    union {
        shoesPutAddEditUserParser addEditUserParser;
        shoesPutRemoveUserParser removeUserParser;
        shoesPutModifyBufferParser modifyBufferParser;
    } putParser;
    shoesResponse response;
} shoesParser;

void shoes_request_parse(shoesParser * parser, buffer * buf);
bool finished_request_parsing(shoesParser* parser);

enum writeResponseStatus {
    WRITE_RESPONSE_SUCCESS = 0x00,
    WRITE_RESPONSE_FAIL = 0x01,
    WRITE_RESPONSE_NOT_DONE = 0x02,
};


enum writeResponseStatus writeResponse(buffer *buf, shoesResponse* response);

