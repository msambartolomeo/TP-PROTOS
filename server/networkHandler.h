#pragma once
#include "socks5.h"

int network_handler(char * socks_addr, char * socks_port, char * shoes_addr,
                    char * shoes_port);
void network_handler_cleanup();
void close_connection(socks5_connection * connection);
const struct fd_handler * get_connection_fd_handler();
