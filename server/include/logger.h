#pragma once
#include "socks5.h"

enum log_type { LOG_ACCESS = 'A', LOG_PASSWORD = 'P' };

void logger(enum log_type type, socks5_connection * conn);
