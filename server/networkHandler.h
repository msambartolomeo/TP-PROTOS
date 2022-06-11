#pragma once
#include "socks5.h"

int network_handler();
void network_handler_cleanup();
void close_connection(socks5_connection * connection);
