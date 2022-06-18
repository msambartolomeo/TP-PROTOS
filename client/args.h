#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include "shoes.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_USERS 10

struct shoesArgs {
    struct shoesUser authUser;

    bool listUsers;
    bool getServerMetrics;
    bool getPasswordSpoofingStatus;

    uint8_t nAddUsers;
    struct shoesUser addUsers[MAX_USERS];

    uint8_t nRemoveUsers;
    char* removeUsers[MAX_USERS];

    uint8_t nEditUsers;
    struct shoesUser editUsers[MAX_USERS];

    bool modifyBufSize;
    uint32_t bufSize;

    bool modifySpoofingStatus;
    bool newSpoofingStatus;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void parse_args(int argc, char** argv, struct shoesArgs* args);

#endif
