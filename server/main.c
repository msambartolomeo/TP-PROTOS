#include "networkHandler.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "args.h"
#include "users.h"

static void
sigterm_handler(const int signal) {
    char* sigtype;
    switch(signal) {
        case SIGTERM:
            sigtype = "SIGTERM";
            break;
        case SIGINT:
            sigtype = "SIGINT";
            break;
        default:
            sigtype = "UNKNOWN";
            break;
    }

    printf("\nsignal %s, cleaning up and exiting...\n",sigtype);
    network_handler_cleanup();
    exit(0);
}

int main(int argc, const char **argv) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    // TODO: remove when args are added
    struct users users[MAX_USERS] = {
        {"pepe", "pepe"}
    };
    initialize_users(users, 1);

    int retcode = network_handler();
    network_handler_cleanup();
    return retcode;
}
