#include "users.h"
#include <string.h>
#include <stdlib.h>

static struct users *userDatabase;
static uint8_t nUsers;
static struct users *shoesUserDatabase;
static uint8_t snUsers;
static bool auth_required = true;

void initialize_users(struct users *users, uint8_t nusers) {
    userDatabase = users;
    nUsers = nusers;
    if (nusers == 0) {
        auth_required = false;
    }
}

void free_users() {
    free(userDatabase);
}

void initialize_shoes_users(struct users *users, uint8_t nusers) {
    shoesUserDatabase = users;
    snUsers = nusers;
}

bool get_auth_state() {
    return auth_required;
}

void change_auth_state(bool required) {
    auth_required = required;
}

int compare_users(const char * one, const char * two) {
    return strcmp(one, two) == 0;
}

static int find_user(char *name) {
    for (int i = 0; i < nUsers; i++) {
        if (compare_users(userDatabase[i].name, name)) {
            return i;
        }
    }
    return -1;
}

static enum authenticationStatus authenticate_user_general(authentication_credentials *credentials, struct users *users, uint8_t n) {
    for (int i = 0; i < n; i++) {
        if (compare_users(users[i].name, (char *) credentials->username) &&
            compare_users(users[i].pass, (char *) credentials->password)) {
            return AUTHENTICATION_STATUS_OK;
        }
    }
    return -1;
}

// TODO replace bool with status enum
bool addUser(char *name, char *pass) {
    if (nUsers == MAX_USERS) {
        return false;
    }
    if (find_user(name) != -1) {
        return false;
    }

    userDatabase[nUsers].name = name;
    userDatabase[nUsers].pass = pass;
    nUsers++;
    return true;
}

bool removeUser(char *name) {
    if (name == NULL ) {
        return false;
    }
    int idx = find_user(name);
    if (idx == -1) {
        return false;
    }
    // TODO: maybe we need to free memory?
    userDatabase[idx].name = userDatabase[nUsers - 1].name;
    userDatabase[idx].pass = userDatabase[nUsers - 1].pass;

    return true;
}

const struct users *authenticate_user(authentication_credentials *credentials) {
    for (int i = 0; i < nUsers; i++) {
        if (compare_users(userDatabase[i].name, (char *) credentials->username) &&
            compare_users(userDatabase[i].pass, (char *) credentials->password)) {
            return &userDatabase[i];
        }
    }
    return NULL;
}

enum authenticationStatus authenticate_shoes_user(authentication_credentials *credentials) {
    return authenticate_user_general(credentials, shoesUserDatabase, snUsers);
}

struct users * get_socks_users(uint8_t * n) {
    *n = nUsers;
    return userDatabase;
}
