#include <errno.h>
#include <getopt.h>
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "args.h"

// static unsigned short port(const char* s) {
//     char* end = 0;
//     const long sl = strtol(s, &end, 10);
//
//     if (end == s || '\0' != *end ||
//         ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
//         sl > USHRT_MAX) {
//         fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
//         exit(1);
//         return 1;
//     }
//     return (unsigned short)sl;
// }

static void user(char * s, struct shoesUser * user) {
    char * p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr,
                "Invalid argument: '%s'.\n Missing password and/or user.\n", s);
        exit(1);
    } else {
        *p = 0;
        p++;

        size_t ulen = strlen(s);
        size_t plen = strlen(p);

        if (ulen > UINT8_MAX || plen > UINT8_MAX) {
            fprintf(stderr, "User or password is too long.\n");
        }

        user->name = s;
        user->pass = p;
    }
}

static void version(void) {
    fprintf(stderr, "shoesc version 0.0\n"
                    "ITBA Protocolos de Comunicación 2022/1 -- Grupo 8\n"
                    "AQUI VA LA LICENCIA\n");
}

static void usage(const char * progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -u <name>:<pass> Usuario admin y contraseña para acceder al "
            "servidor SHOES\n"
            "   -g               Lista los usuarios.\n"
            "   -m               Muestra las métricas del servidor.\n"
            "   -s               Muestra el estado del password spoofing.\n"
            "   -s1              Enciende el password spoofing\n"
            "   -s0              Desactiva el password spoofing\n"
            "   -b <size>        Cambia el tamaño del buffer\n"
            "   -a <name>:<pass> Agrega un nuevo usuario\n"
            "   -r <name>        Elimina un usuario\n"
            "   -e <name>:<pass> Edita un usuario\n"
            "   -l <FQDN/IP>     Dirección del proxy a configurar\n"
            "   -p <puerto>      Puerto del servicio de management del proxy\n"
            "   -v               Imprime información sobre la versión de shoesc"
            "y termina.\n"
            "\n",
            progname);
    exit(1);
}

void spoof(const char * s, struct shoesArgs * args) {
    if (s == NULL) {
        args->getPasswordSpoofingStatus = true;
        return;
    }

    switch (*s) {
    case '1':
        args->modifySpoofingStatus = true;
        args->newSpoofingStatus = true;
        break;
    case '0':
        args->modifySpoofingStatus = true;
        args->newSpoofingStatus = false;
        break;
    default:
        args->getPasswordSpoofingStatus = true;
        break;
    }
}

void buf(const char * s, struct shoesArgs * args) {
    char * endptr;
    long val = strtol(s, &endptr, 0);

    if (errno || endptr == s) {
        fprintf(stderr, "Invalid buffer size\n");
        exit(1);
    }

    args->modifyBufSize = true;
    args->bufSize = val;
}

void parse_args(const int argc, char ** argv, struct shoesArgs * args) {
    memset(args, 0, sizeof(*args));

    int c;

    while (true) {
        c = getopt(argc, argv, "hgms::u:a:e:r:b:l:p:v");
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage("shoesc");
            break;
        case 'g':
            args->listUsers = true;
            break;
        case 'm':
            args->getServerMetrics = true;
            break;
        case 's':
            spoof(optarg, args);
            break;
        case 'u':
            user(optarg, &args->authUser);
            break;
        case 'a':
            user(optarg, &args->addUsers[args->nAddUsers++]);
            break;
        case 'e':
            user(optarg, &args->editUsers[args->nEditUsers++]);
            break;
        case 'r':
            args->removeUsers[args->nRemoveUsers++] = optarg;
            break;
        case 'b':
            buf(optarg, args);
            break;
        case 'p':
            args->usePort = true;
            args->port = optarg;
            break;
        case 'l':
            args->useAddr = true;
            args->addr = optarg;
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
