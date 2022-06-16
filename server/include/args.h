#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include <stdint.h>

#define MAX_USERS 10

struct socks5args {
    char *socks_addr;
    char *socks_port;

    char *shoes_addr;
    char *shoes_port;

    bool disectors_enabled;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void 
parse_args(int argc, char* const *argv, struct socks5args *args);

#endif

