#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct shoes_user {
    char * name;
    char * pass;
} shoes_user;

typedef enum shoes_family { SHOES_GET = 0, SHOES_PUT } shoes_family;

typedef enum shoes_put_command {
    CMD_ADD_USER = 0,
    CMD_REMOVE_USER,
    CMD_EDIT_USER,
    CMD_MODIFY_BUFFER,
    CMD_MODIFY_SPOOF,
} shoes_put_command;

typedef enum shoes_get_command {
    CMD_METRICS = 0,
    CMD_LIST_USERS,
    CMD_GET_SPOOF,
} shoes_get_command;

typedef enum shoes_connect_status {
    CONNECT_SUCCESS = 0,
    CONNECT_SERV_FAIL,
    CONNECT_INVALID_VER,
    CONNNECT_INVALID_USER
} shoes_connect_status;

shoes_connect_status shoes_connect(const char * host, const char * port,
                                   const shoes_user * user);

typedef enum shoes_response_status {
    RESPONSE_SUCCESS = 0,
    RESPONSE_SERV_FAIL,
    RESPONSE_FMLY_NOT_SUPPORTED,
    RESPONSE_CMD_NOT_SUPPORTED,
    RESPONSE_CMD_FAIL_04,
    RESPONSE_CMD_FAIL_05,
} shoes_response_status;

typedef struct shoes_server_metrics {
    uint32_t historic_connections;
    uint32_t current_connections;
    uint64_t bytes_transferred;
} shoes_server_metrics;
shoes_response_status shoes_get_metrics(shoes_server_metrics * metrics);

typedef struct shoes_user_list {
    uint8_t u_count;
    char ** users;
} shoes_user_list;
shoes_response_status shoes_get_user_list(shoes_user_list * list);

shoes_response_status shoes_get_spoofing_status(bool * status);

shoes_response_status shoes_add_user(const shoes_user * user);
shoes_response_status shoes_remove_user(const char * user);
shoes_response_status shoes_edit_user(const shoes_user * user);

shoes_response_status shoes_modify_buffer_size(uint16_t size);
shoes_response_status shoes_modify_password_spoofing_status(bool new_status);

const char * shoes_human_readable_status();

void shoes_close_connection();

void free_shoes_user(shoes_user * user);
void free_shoes_user_list(shoes_user_list * list);
