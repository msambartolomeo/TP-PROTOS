#include "args.h"
#include "metrics.h"
#include "networkHandler.h"
#include "users.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void sigterm_handler(const int signal) {
    char * sigtype;
    switch (signal) {
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

    printf("\nsignal %s, cleaning up and exiting...\n", sigtype);
    network_handler_cleanup();
    free_users();
    exit(0);
}

int main(int argc, char * const * argv) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    close(STDIN_FILENO);

    struct socks5args args;
    parse_args(argc, argv, &args);

    struct user shoes_users[MAX_USERS] = {{"shoes", "shoes"}};
    initialize_shoes_users(shoes_users, 1);
    // TODO Properly initialize_shoes_users();
    init_metrics();

    int retcode = network_handler(args.socks_addr, args.socks_port,
                                  args.shoes_addr, args.shoes_port);

    network_handler_cleanup();
    free_users();

    return retcode;
}
