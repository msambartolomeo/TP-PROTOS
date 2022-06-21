#include <stdint.h>

void init_metrics();

void reportNewSocksConnection();
void reportClosedSocksConnection();
void reportTransferBytes(uint64_t bytes);

void reportNewShoesConnection();
void reportClosedShoesConnection();

uint32_t getHistoricConnections();
uint32_t getSocksCurrentConnections();
uint64_t getBytesTransferred();

uint32_t getShoesCurrentConnections();
