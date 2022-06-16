#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "args.h"
#include "users.h"

static char *port(char *s) {
    char *end     = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        return NULL;
    }
    return s;
}

static void user(char *s, struct users *user) {
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }
}

static void version(void) {
    fprintf(stderr, "socks5v version 0.0\n"
                    "ITBA Protocolos de Comunicación 2022/1 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
        "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseña de usuario que puede usar el proxy. Hasta 10.\n"
        "   -v               Imprime información sobre la versión versión y termina.\n"
        "\n",
        progname);
}

void parse_args(int argc, char* const *argv, struct socks5args *args) {
    memset(args, 0, sizeof(*args));

    args->socks_addr = NULL;
    args->socks_port = "1080";

    args->shoes_addr   = NULL;
    args->shoes_port   = "8080";

    args->disectors_enabled = true;

    int c;

    int nusers = 0;
    struct users *users = malloc(sizeof(struct users) * MAX_USERS);
    if (users == NULL) {
      fprintf(stderr, "Error allocating memory for user database\n");
      exit(1);
    }

    while (true) {
        c = getopt(argc, argv, "hl:L:Np:P:u:v");
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                free(users);
                exit(0);
                break;
            case 'l':
                args->socks_addr = optarg;
                break;
            case 'L':
                args->shoes_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'p':
                args->socks_port = port(optarg);
                if (args->socks_port == NULL) {
                    free(users);
                    exit(1);
                }
                break;
            case 'P':
                args->shoes_port = port(optarg);
                if (args->shoes_port == NULL) {
                    free(users);
                    exit(1);
                }
                break;
            case 'u':
                if(nusers >= MAX_USERS) {
                    fprintf(stderr, "maximum number of command line users reached: %d.\n", MAX_USERS);
                    free(users);
                    exit(1);
                } else {
                    user(optarg, users + nusers);
                    nusers++;
                }
                break;
            case 'v':
                version();
                free(users);
                exit(0);
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                free(users);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        free(users);
        exit(1);
    }

    initialize_users(users, nusers);
}
