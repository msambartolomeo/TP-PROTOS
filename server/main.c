#include "networkHandler.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

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
    networkHandlerCleanup();
    exit(0);
}

int main(int argc, const char **argv) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    int retcode = networkHandler();
    networkHandlerCleanup();
    return retcode;
}
