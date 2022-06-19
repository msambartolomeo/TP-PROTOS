#pragma once
#include "socks5.h"

enum logType {
    LOG_ACCESS = 'A',
    LOG_PASSWORD = 'P'
};

void logger(enum logType type, socks5_connection *conn);
