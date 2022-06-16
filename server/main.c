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

int main(int argc, char* const *argv) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    struct socks5args args;
    parse_args(argc, argv, &args);

    int retcode = network_handler(args.socks_addr, args.socks_port, args.shoes_addr, args.shoes_port);
    network_handler_cleanup();
    free_users();

    return retcode;
}
