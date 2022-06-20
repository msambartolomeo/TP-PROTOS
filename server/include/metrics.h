#include <stdint.h>

void init_metrics();

void report_new_connection();
void report_closed_connection();
void report_transfer_bytes(uint64_t bytes);

uint32_t get_historic_connections();
uint32_t get_concurrent_connections();
uint64_t get_bytes_transferred();

