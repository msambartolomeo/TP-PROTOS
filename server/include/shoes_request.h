#pragma once

#include "buffer.h"
#include <stdint.h>
#include <stdlib.h>

#define USERNAME_MAX_LENGTH 256
#define PASSWORD_MAX_LENGTH 256
#define BUFSIZE_MIN_LENGTH 512

enum shoes_family {
    SHOES_GET = 0x00,
    SHOES_PUT = 0x01,
};

enum shoes_get_commands {
    CMD_METRICS = 0x00,
    CMD_LIST_USERS = 0x01,
    CMD_SPOOFING_STATUS = 0x02,
};

enum shoes_put_commands {
    CMD_ADD_USER = 0x00,
    CMD_REMOVE_USER = 0x01,
    CMD_EDIT_USER = 0x02,
    CMD_MODIFY_BUFFER = 0x03,
    CMD_MODIFY_SPOOF = 0x04,
};

enum shoes_parse_state {
    PARSE_FMLY,
    PARSE_CMD,
    PARSE_DATA,
    PARSE_DONE,
    PARSE_ERROR_UNSUPPORTED_FMLY,
    PARSE_ERROR_UNSUPPORTED_CMD,
};

enum shoes_put_add_edit_user_state {
    PARSE_ADD_EDIT_USER_ULEN,
    PARSE_ADD_EDIT_USER_USER,
    PARSE_ADD_EDIT_USER_PLEN,
    PARSE_ADD_EDIT_USER_PASS
};

enum shoes_put_remove_user_state {
    PARSE_REMOVE_USER_ULEN,
    PARSE_REMOVE_USER_USER
};

enum shoes_put_modify_buffer_state {
    PARSE_BUFFER_SIZE,
    PARSE_BUFFER_DONE,
    PARSE_ERROR_BUFSIZE_OUT_OF_RANGE,
};

typedef struct shoes_put_add_edit_user_parser {
    enum shoes_put_add_edit_user_state state;
    uint8_t username[USERNAME_MAX_LENGTH];
    uint8_t password[PASSWORD_MAX_LENGTH];
    uint8_t remaining;
    uint8_t * pointer;
} shoes_put_add_edit_user_parser;

typedef struct shoes_put_remove_user_parser {
    enum shoes_put_remove_user_state state;
    uint8_t username[USERNAME_MAX_LENGTH];
    uint8_t remaining;
    uint8_t * pointer;
} shoes_put_remove_user_parser;

typedef struct shoes_put_modify_buffer_parser {
    enum shoes_put_modify_buffer_state state;
    uint16_t buffer_size;
    uint8_t remaining;
    uint8_t * pointer;
} shoes_put_modify_buffer_parser;

typedef enum shoes_response_status {
    RESPONSE_SUCCESS = 0x00,
    RESPONSE_SERV_FAIL = 0x01,
    RESPONSE_FMLY_NOT_SUPPORTED = 0x02,
    RESPONSE_CMD_NOT_SUPPORTED = 0x03,
    RESPONSE_CMD_FAIL_04 = 0x04,
    RESPONSE_CMD_FAIL_05 = 0x05
} shoes_response_status;

typedef struct shoes_response {
    shoes_response_status status;
    uint8_t * data;
    size_t data_size;
    size_t remaining;
} shoes_response;

typedef struct shoes_parser {
    enum shoes_parse_state state;
    enum shoes_family family;
    union {
        enum shoes_get_commands get;
        enum shoes_put_commands put;
    } cmd;
    void (*parse)(struct shoes_parser * parser, uint8_t byte);
    union {
        shoes_put_add_edit_user_parser add_edit_user_parser;
        shoes_put_remove_user_parser remove_user_parser;
        shoes_put_modify_buffer_parser modify_buffer_parser;
    } put_parser;
    shoes_response response;
} shoes_parser;

void shoes_request_parse(shoes_parser * parser, buffer * buf);
bool finished_request_parsing(shoes_parser * parser);

enum write_response_status {
    WRITE_RESPONSE_SUCCESS = 0x00,
    WRITE_RESPONSE_FAIL = 0x01,
    WRITE_RESPONSE_NOT_DONE = 0x02,
};

enum write_response_status write_response(buffer * buf,
                                          shoes_response * response);
