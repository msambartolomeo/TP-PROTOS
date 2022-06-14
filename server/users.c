#include "users.h"
#include <string.h>

static struct users *userDatabase;
static uint8_t nUsers;

void initialize_users(struct users *users, uint8_t nusers) {
    userDatabase = users;
    nUsers = nusers;
}

int compare_users(char * one, char * two) {
    return strcmp(one, two);
}


enum authenticationStatus authenticate_user(authentication_credentials *credentials) {
    for (int i = 0; i < nUsers; i++) {
        if (compare_users(userDatabase[i].name, (char *) credentials->username) == 0 &&
            compare_users(userDatabase[i].pass, (char *) credentials->password) == 0) {
            return AUTHENTICATION_STATUS_OK;
        }
    }
    return AUTHENTICATION_STATUS_FAILED;
}
