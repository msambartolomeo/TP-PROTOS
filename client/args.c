#include <getopt.h>
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "args.h"

//static unsigned short port(const char* s) {
//    char* end = 0;
//    const long sl = strtol(s, &end, 10);
//
//    if (end == s || '\0' != *end ||
//        ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
//        sl > USHRT_MAX) {
//        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
//        exit(1);
//        return 1;
//    }
//    return (unsigned short)sl;
//}

static void user(char* s, struct shoesUser* user) {
    char* p = strchr(s, ':');
    if (p == NULL) {
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
    fprintf(stderr, "shoesc version 0.0\n"
                    "ITBA Protocolos de Comunicación 2022/1 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}

static void list(char* s, struct shoesArgs* args) {
    if(strcmp(s, "u") == 0)
        args->listUsers = true;
    else if(strcmp(s, "c") == 0)
        args -> listCredentials = true;
    else {
        fprintf(stderr, "Unknown argument: -l%s", s);
        exit(1);
    }
}

static void usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -lu              Lista los usuarios.\n"
            "   -lc              Lista las credenciales.\n"
            "   -m               Muestra las métricas del servidor.\n"
            "   -s               Muestra el estado del password spoofing.\n"
            "   -u <name>:<pass> Usuario y contraseña para acceder al servidor SHOES\n"
            "   -v               Imprime información sobre la versión de shoesc"
            "y termina.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char** argv, struct shoesArgs* args) {
    memset(
        args, 0,
        sizeof(*args));


    int c;

    while (true) {
        c = getopt(argc, argv, "hl:msu:v");
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage("shoesc");
            break;
        case 'l':
            list(optarg, args);
            break;
        case 'm':
            args->getServerMetrics = true;
            break;
        case 's':
            args->getPasswordSpoofingStatus = true;
            break;
        case 'u':
            user(optarg, &args->authUser);
            break;
        case 'v':
            version();
            exit(0);
            break;
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
            exit(1);
        }
    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
            optind++;
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
