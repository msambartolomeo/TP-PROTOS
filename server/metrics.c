#include "metrics.h"

static uint32_t historicConnections;
static uint32_t concurrentConnections;
static uint32_t bytesTransferred;

void init_metrics() {
    historicConnections = 0;
    concurrentConnections = 0;
    bytesTransferred = 0;
}

void report_new_connection() {
    historicConnections++;
    concurrentConnections++;
}

void report_closed_connection() {
    concurrentConnections--;
}

void report_transfer_bytes(uint32_t bytes) {
    bytesTransferred += bytes;
}

uint32_t get_historic_connections() {
    return historicConnections;
}
uint32_t get_concurrent_connections() {
    return concurrentConnections;
}
uint32_t get_bytes_transferred() {
    return bytesTransferred;
}
