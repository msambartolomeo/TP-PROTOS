#include "args.h"
#include "shoes.h"
#include <stdio.h>
#include <stdlib.h>

static void listUsers() {
    shoesUserList list;
    if (shoesGetUserList(&list) != RESPONSE_SUCCESS) {
        fprintf(stderr, "List Users Error: %s",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nUSERS:\n");
    for (uint32_t i = 0; i < list.n; i++) {
        printf("%s\n", list.users[i]);
    }

    freeShoesUserList(&list);
}

static void getServerMetrics() {
    shoesServerMetrics metrics;
    if (shoesGetMetrics(&metrics) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Get Metrics Error: %s",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nServer Metrics: \n");
    printf("----------------\n");
    printf("Historic Connections: %u\n", metrics.historicConnections);
    printf("Current Connections: %u\n", metrics.currentConnections);
    printf("Bytes Transferred: %u\n", metrics.bytesTransferred);
}

void getPasswordSpoofingStatus() {
    bool spoofStatus;
    if (shoesGetSpoofingStatus(&spoofStatus) !=
        RESPONSE_SUCCESS) {
        fprintf(stderr, "Get spoof status error: %s",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("\nSpoof Status: \n%s\n", spoofStatus ? "ON" : "OFF");
}

void modifyBufSize(uint32_t size) {
    if (shoesModifyBufferSize(size) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Modify bufsize error: %s",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("Buffer size modified successfully\n");
}

void addUsers(struct shoesUser* users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesAddUser(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Add user error: %s",
                    shoesHumanReadableStatus()); // TODO: better error printing
            return;
        }

        printf("User '%s' added successfully\n", users[i].name);
    }
}

void editUsers(struct shoesUser* users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesEditUser(&users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Edit user error: %s",
                    shoesHumanReadableStatus()); // TODO: better error printing
            return;
        }

        printf("User '%s' edited successfully\n", users[i].name);
    }
}

void removeUsers(char** users, uint8_t len) {
    for (int i = 0; i < len; i++) {
        if (shoesRemoveUser(users[i]) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Remove user error: %s",
                    shoesHumanReadableStatus()); // TODO: better error printing
            return;
        }

        printf("User '%s' removed successfully\n", users[i]);
    }
}

void modifySpoofingStatus(bool newStatus) {
    if (shoesModifyPasswordSpoofingStatus(newStatus) !=
        RESPONSE_SUCCESS) {
        fprintf(stderr, "Modify spoofing status error: %s",
                shoesHumanReadableStatus()); // TODO: better error printing
        return;
    }

    printf("Spoofing status updated successfully\n");
}

int main(int argc, char** argv) {
    struct shoesArgs args;
    parse_args(argc, argv, &args);

    if (args.authUser.name == NULL) {
        fprintf(stderr, "Admin credentials not included.\n");
        return 1;
    }

    if (shoesConnect("127.0.0.1", "8080", &args.authUser) !=
        CONNECT_SUCCESS) {
        fprintf(stderr, "Connect error: %s\n",
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

    return 0;
}
