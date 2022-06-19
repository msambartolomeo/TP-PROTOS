#include "users.h"
#include <string.h>

static struct users *userDatabase;
static uint8_t nUsers;
static struct users *shoesUserDatabase;
static uint8_t snUsers;

void initialize_users(struct users *users, uint8_t nusers) {
    userDatabase = users;
    nUsers = nusers;
}

void initialize_shoes_users(struct users *users, uint8_t nusers) {
    shoesUserDatabase = users;
    snUsers = nusers;
}

int compare_users(char * one, char * two) {
    return strcmp(one, two);
}

static enum authenticationStatus authenticate_user_general(authentication_credentials *credentials, struct users *users, uint8_t n) {
    for (int i = 0; i < n; i++) {
        if (compare_users(users[i].name, (char *) credentials->username) == 0 &&
            compare_users(users[i].pass, (char *) credentials->password) == 0) {
            return AUTHENTICATION_STATUS_OK;
        }
    }
    return AUTHENTICATION_STATUS_FAILED;
}

enum authenticationStatus authenticate_user(authentication_credentials *credentials) {
    return authenticate_user_general(credentials, userDatabase, nUsers);
}

enum authenticationStatus authenticate_shoes_user(authentication_credentials *credentials) {
    return authenticate_user_general(credentials, shoesUserDatabase, snUsers);
}

struct users * get_socks_users(uint8_t * n) {
    *n = nUsers;
    return userDatabase;
}
