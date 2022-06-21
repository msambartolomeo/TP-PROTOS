#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include "shoes.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_USERS 10

struct shoes_args {
    struct shoes_user auth_user;

    bool use_addr;
    bool use_port;
    char * addr;
    char * port;

    bool list_users;
    bool get_server_metrics;
    bool get_password_spoofing_status;

    uint8_t n_add_users;
    struct shoes_user add_users[MAX_USERS];

    uint8_t n_remove_users;
    char * remove_users[MAX_USERS];

    uint8_t n_edit_users;
    struct shoes_user edit_users[MAX_USERS];

    bool modify_buf_size;
    uint16_t buf_size;

    bool modify_spoofing_status;
    bool new_spoofing_status;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(int argc, char ** argv, struct shoes_args * args);

#endif
