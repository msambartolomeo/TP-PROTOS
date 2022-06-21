#include "args.h"
#include "shoes.h"
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT "8080"

static void list_users() {
    shoes_user_list list;
    if (shoes_get_user_list(&list) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nList Users Error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
        return;
    }

    printf("\nUSERS:\n");
    for (uint8_t i = 0; i < list.u_count; i++) {
        printf("%d: %s\n", i + 1, list.users[i]);
    }

    free_shoes_user_list(&list);
}

static void get_server_metrics() {
    shoes_server_metrics metrics;
    if (shoes_get_metrics(&metrics) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nGet Metrics Error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
        return;
    }

    printf("\nServer Metrics: \n");
    printf("----------------\n");
    printf("Historic Connections: %u\n", metrics.historic_connections);
    printf("Current Connections: %u\n", metrics.current_connections);
    printf("Bytes Transferred: %lu\n", metrics.bytes_transferred);
}

void get_password_spoofing_status() {
    bool spoof_status;
    if (shoes_get_spoofing_status(&spoof_status) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nGet spoof status error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
        return;
    }

    printf("\nSpoof Status: \n%s\n", spoof_status ? "ON" : "OFF");
}

void modify_buf_size(uint32_t size) {
    if (shoes_modify_buffer_size(size) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nModify bufsize error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
        return;
    }

    printf("\nBuffer size modified successfully\n");
}

void add_users(struct shoes_user * users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoes_add_user(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(
                stderr, "\nAdd user error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
            return;
        }

        printf("\nUser '%s' added successfully\n", users[i].name);
    }
}

void edit_users(struct shoes_user * users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoes_edit_user(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(
                stderr, "\nEdit user error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
            return;
        }

        printf("\nUser '%s' edited successfully\n", users[i].name);
    }
}

void remove_users(char ** users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoes_remove_user(users[i]) != RESPONSE_SUCCESS) {
            fprintf(
                stderr, "\nRemove user error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
            // TODO: @Agus esto falla cuando mandas un usuario inexistente, pero
            // debería decir que no se pudo eliminar porque no existe, no que
            // falló.
            return;
        }

        printf("\nUser '%s' removed successfully\n", users[i]);
    }
}

void modify_spoofing_status(bool new_status) {
    if (shoes_modify_password_spoofing_status(new_status) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nModify spoofing status error: %s\n",
                shoes_human_readable_status()); // TODO: better error printing
        return;
    }

    printf("\nSpoofing status updated successfully\n");
}

int main(int argc, char ** argv) {
    struct shoes_args args;
    parse_args(argc, argv, &args);

    if (args.auth_user.name == NULL) {
        fprintf(stderr, "\nAdmin credentials not included.\n");
        return 1;
    }

    char * addr = DEFAULT_ADDR;
    char * port = DEFAULT_PORT;

    if (args.use_port) {
        port = args.port;
    }
    if (args.use_addr) {
        addr = args.addr;
    }

    if (shoes_connect(addr, port, &args.auth_user) != CONNECT_SUCCESS) {
        fprintf(stderr, "\nConnect error: %s\n", shoes_human_readable_status());
        return 1;
    }

    //SETTERS
    if (args.modify_buf_size)
        modify_buf_size(args.buf_size);
    if (args.modify_spoofing_status)
        modify_spoofing_status(args.new_spoofing_status);
    if (args.n_add_users > 0)
        add_users(args.add_users, args.n_add_users);
    if (args.n_edit_users > 0)
        edit_users(args.edit_users, args.n_edit_users);
    if (args.n_remove_users > 0)
        remove_users(args.remove_users, args.n_remove_users);

    //GETTERS
    if (args.list_users)
        list_users();
    if (args.get_server_metrics)
        get_server_metrics();
    if (args.get_password_spoofing_status)
        get_password_spoofing_status();

    shoes_close_connection();

    return 0;
}
