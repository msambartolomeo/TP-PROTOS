#include <stdint.h>

void init_metrics();

void report_new_socks_connection();
void report_closed_socks_connection();
void report_transfer_bytes(uint64_t bytes);

void report_new_shoes_connection();
void report_closed_shoes_connection();

uint32_t get_historic_connections();
uint32_t get_socks_current_connections();
uint64_t get_bytes_transferred();

uint32_t get_shoes_current_connections();
