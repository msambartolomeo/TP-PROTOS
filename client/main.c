#include "args.h"
#include "shoes.h"
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT "8080"

static void listUsers() {
    shoesUserList list;
    if (shoesGetUserList(&list) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nList Users Error: %s\n",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nUSERS:\n");
    for (uint8_t i = 0; i < list.uCount; i++) {
        printf("%d: %s\n", i+1, list.users[i]);
    }

    freeShoesUserList(&list);
}

static void getServerMetrics() {
    shoesServerMetrics metrics;
    if (shoesGetMetrics(&metrics) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nGet Metrics Error: %s\n",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nServer Metrics: \n");
    printf("----------------\n");
    printf("Historic Connections: %u\n", metrics.historicConnections);
    printf("Current Connections: %u\n", metrics.currentConnections);
    printf("Bytes Transferred: %lu\n", metrics.bytesTransferred);
}

void getPasswordSpoofingStatus() {
    bool spoofStatus;
    if (shoesGetSpoofingStatus(&spoofStatus) !=
        RESPONSE_SUCCESS) {
        fprintf(stderr, "\nGet spoof status error: %s\n",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nSpoof Status: \n%s\n", spoofStatus ? "ON" : "OFF");
}

void modifyBufSize(uint32_t size) {
    if (shoesModifyBufferSize(size) != RESPONSE_SUCCESS) {
        fprintf(stderr, "\nModify bufsize error: %s\n",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nBuffer size modified successfully\n");
}

void addUsers(struct shoesUser* users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesAddUser(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "\nAdd user error: %s\n",
                    shoesHumanReadableStatus()); // TODO: better error printing
            return;
        }

        printf("\nUser '%s' added successfully\n", users[i].name);
    }
}

void editUsers(struct shoesUser* users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesEditUser(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "\nEdit user error: %s\n",
                    shoesHumanReadableStatus()); // TODO: better error printing
            return;
        }

        printf("\nUser '%s' edited successfully\n", users[i].name);
    }
}

void removeUsers(char** users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesRemoveUser(users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "\nRemove user error: %s\n",
                    shoesHumanReadableStatus()); // TODO: better error printing
                    // TODO: @Agus esto falla cuando mandas un usuario inexistente, pero debería decir que no se pudo eliminar
                    // porque no existe, no que falló.
            return;
        }

        printf("\nUser '%s' removed successfully\n", users[i]);
    }
}

void modifySpoofingStatus(bool newStatus) {
    if (shoesModifyPasswordSpoofingStatus(newStatus) !=
        RESPONSE_SUCCESS) {
        fprintf(stderr, "\nModify spoofing status error: %s\n",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nSpoofing status updated successfully\n");
}

int main(int argc, char** argv) {
    struct shoesArgs args;
    parse_args(argc, argv, &args);

    if (args.authUser.name == NULL) {
        fprintf(stderr, "\nAdmin credentials not included.\n");
        return 1;
    }

    char* addr = DEFAULT_ADDR;
    char* port = DEFAULT_PORT;

    if(args.usePort) {
        port = args.port;
    }
    if(args.useAddr) {
        addr = args.addr;
    }

    if (shoesConnect(addr, port, &args.authUser) !=
        CONNECT_SUCCESS) {
        fprintf(stderr, "\nConnect error: %s\n",
                shoesHumanReadableStatus());
        return 1;
    }

    if (args.listUsers)
        listUsers();
    if (args.getServerMetrics)
        getServerMetrics();
    if (args.getPasswordSpoofingStatus)
        getPasswordSpoofingStatus();
    if (args.modifyBufSize)
        modifyBufSize(args.bufSize);
    if (args.nAddUsers > 0)
        addUsers(args.addUsers, args.nAddUsers);
    if (args.nEditUsers > 0)
        editUsers(args.editUsers, args.nEditUsers);
    if (args.nRemoveUsers > 0)
        removeUsers(args.removeUsers, args.nRemoveUsers);
    if (args.modifySpoofingStatus)
        modifySpoofingStatus(args.newSpoofingStatus);

    shoesCloseConnection();

    return 0;
}
