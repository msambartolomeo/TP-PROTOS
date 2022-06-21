#include "metrics.h"

static uint32_t historic_connections;
static uint32_t socks_current_connections;
static uint32_t shoes_current_connections;
static uint64_t bytes_transferred;

void init_metrics() {
    historic_connections = 0;
    socks_current_connections = 0;
    bytes_transferred = 0;
}

void report_new_socks_connection() {
    historic_connections++;
    socks_current_connections++;
}

void report_closed_socks_connection() { socks_current_connections--; }

void report_new_shoes_connection() { shoes_current_connections++; }

void report_closed_shoes_connection() { shoes_current_connections--; }

void report_transfer_bytes(uint64_t bytes) { bytes_transferred += bytes; }

uint32_t get_historic_connections() { return historic_connections; }
uint32_t get_socks_current_connections() { return socks_current_connections; }
uint64_t get_bytes_transferred() { return bytes_transferred; }

uint32_t get_shoes_current_connections() { return shoes_current_connections; }
