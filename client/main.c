#include "args.h"
#include "shoes.h"
#include <stdio.h>
#include <stdlib.h>

static void listUsers() {
    shoesUserList list;
    shoesResponseStatus status;
    if((status = shoesGetUserList(&list)) != RESPONSE_SUCCESS) {
        fprintf(stderr, "List Users Error: Code %d", status); //TODO: better error printing
        return;
    }

    printf("\nUSERS:\n");
    for(uint32_t i = 0; i < list.n; i++) {
        printf("%s\n", list.users[i]);
    }

    freeShoesUserList(&list);
}

static void getServerMetrics() {
    shoesServerMetrics metrics;
    shoesResponseStatus status;
    if ((status = shoesGetMetrics(&metrics)) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Get Metrics Error: Code %d", status); //TODO: better error printing
        return;
    }

    printf("\nServer Metrics: \n");
    printf("Bytes Transerred: %d\n", metrics.bytesTransferred);
    printf("Current Connections: %d\n", metrics.currentConnections);
    printf("Historic Connections: %d\n", metrics.historicConnections);
}

void getPasswordSpoofingStatus() {
    bool spoofStatus;
    shoesResponseStatus responseStatus;
    if ((responseStatus = shoesGetSpoofingStatus(&spoofStatus)) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Get spoof status error: Code %d", responseStatus); //TODO: better error printing
        return;
    }

    printf("\nSpoof Status: \n%s\n", spoofStatus ? "ON" : "OFF");
}

void modifyBufSize(uint32_t size) {
    shoesResponseStatus responseStatus;
    if((responseStatus = shoesModifyBufferSize(size)) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Modify bufsize error: Code %d", responseStatus); //TODO: better error printing
        return;
    }

    printf("Buffer size modified successfully\n");
}

void addUsers(struct shoesUser* users, uint8_t len) {
    for(int i = 0; i < len; i++) {
        shoesResponseStatus responseStatus;
        if((responseStatus = shoesAddUser(&users[i])) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Add user error: Code %d", responseStatus); //TODO: better error printing
            return;
        }

        printf("User '%s' added successfully\n", users[i].name);
    }
}

void editUsers(struct shoesUser* users, uint8_t len) {
    for(int i = 0; i < len; i++) {
        shoesResponseStatus responseStatus;
        if((responseStatus = shoesEditUser(&users[i])) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Edit user error: Code %d", responseStatus); //TODO: better error printing
            return;
        }

        printf("User '%s' edited successfully\n", users[i].name);
    }
}

void removeUsers(char** users, uint8_t len) {
    for(int i = 0; i < len; i++) {
        shoesResponseStatus responseStatus;
        if((responseStatus = shoesRemoveUser(users[i])) != RESPONSE_SUCCESS) {
            fprintf(stderr, "Remove user error: Code %d", responseStatus); //TODO: better error printing
            return;
        }

        printf("User '%s' removed successfully\n", users[i]);
    }
}

void modifySpoofingStatus(bool newStatus) {
    shoesResponseStatus responseStatus;
    if((responseStatus = shoesModifyPasswordSpoofingStatus(newStatus)) != RESPONSE_SUCCESS) {
        fprintf(stderr, "Modify bufsize error: Code %d", responseStatus); //TODO: better error printing
        return;
    }

    printf("Spoofing status updated successfully\n");
}

int main(int argc, char** argv) {
    struct shoesArgs args;
    parse_args(argc, argv, &args);

    if(args.authUser.name == NULL) {
        fprintf(stderr, "Admin credentials not included.\n");
        return 1;
    }

    shoesConnectStatus status;
    if((status = shoesConnect("127.0.0.1", "1081", &args.authUser)) != CONNECT_SUCCESS) {
        fprintf(stderr, "Connect error: Code %d\n", status);
        return 1;
    }

    if(args.listUsers) listUsers();
    if(args.getServerMetrics) getServerMetrics();
    if(args.getPasswordSpoofingStatus) getPasswordSpoofingStatus();
    if(args.modifyBufSize) modifyBufSize(args.bufSize);
    if(args.nAddUsers > 0) addUsers(args.addUsers, args.nAddUsers);
    if(args.nEditUsers > 0) editUsers(args.editUsers, args.nEditUsers);
    if(args.nRemoveUsers > 0) removeUsers(args.removeUsers, args.nRemoveUsers);
    if(args.modifySpoofingStatus) modifySpoofingStatus(args.newSpoofingStatus);

    return 0;
}
