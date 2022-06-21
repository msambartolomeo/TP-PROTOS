#include "metrics.h"

static uint32_t historicConnections;
static uint32_t socksCurrentConnections;
static uint32_t shoesCurrentConnections;
static uint64_t bytesTransferred;

void init_metrics() {
    historicConnections = 0;
    socksCurrentConnections = 0;
    bytesTransferred = 0;
}

void reportNewSocksConnection() {
    historicConnections++;
    socksCurrentConnections++;
}

void reportClosedSocksConnection() { socksCurrentConnections--; }

void reportNewShoesConnection() { shoesCurrentConnections++; }

void reportClosedShoesConnection() { shoesCurrentConnections--; }

void reportTransferBytes(uint64_t bytes) { bytesTransferred += bytes; }

uint32_t getHistoricConnections() { return historicConnections; }
uint32_t getSocksCurrentConnections() { return socksCurrentConnections; }
uint64_t getBytesTransferred() { return bytesTransferred; }

uint32_t getShoesCurrentConnections() { return shoesCurrentConnections; }
