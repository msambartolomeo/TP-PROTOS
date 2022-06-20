#include "users.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static struct user *userDatabase[MAX_USERS];
static uint8_t nUsers;
static struct user *shoesUserDatabase[MAX_SHOES_USERS];
static uint8_t snUsers;
static bool auth_required = false;

void free_users() {
    for (uint8_t i = 0; i < nUsers; i++) {
        free(userDatabase[i]->name);
        free(userDatabase[i]->pass);
        free(userDatabase[i]);
    }
    nUsers = 0;
    auth_required = false;
}

void initialize_shoes_users(struct user *users, uint8_t nusers) {
    *shoesUserDatabase = users;
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
        if (compare_users(userDatabase[i]->name, name)) {
            return i;
        }
    }
    return -1;
}

// TODO replace bool with status enum
enum addUserResponse addUser(char *name, char *pass) {
    if (nUsers == MAX_USERS) {
        return ADD_USER_MAX_REACHED;
    }
    if (find_user(name) != -1) {
        return ADD_USER_ALREADY_EXISTS;
    }

    userDatabase[nUsers] = malloc(sizeof(struct user));
    if (userDatabase[nUsers] == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    size_t ulen = strlen(name);
    size_t plen = strlen(pass);
    userDatabase[nUsers]->name = malloc(ulen + 1);
    userDatabase[nUsers]->pass = malloc(plen + 1);
    if (name == NULL || pass == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    strcpy(userDatabase[nUsers]->name, name);
    strcpy(userDatabase[nUsers]->pass, pass);
    if (nUsers == 0) {
        auth_required = true;
    }
    nUsers++;
    return ADD_USER_SUCCESS;
}

enum editUserResponse editUser(char *name, char *pass) {
    int i = find_user(name);
    if (i == -1) {
        return EDIT_USER_NOT_FOUND;
    }
    size_t pLen = strlen(pass);
    userDatabase[i]->pass = realloc(userDatabase[i]->pass, pLen + 1);
    if (userDatabase[i]->pass == NULL) {
        return EDIT_USER_SERV_ERROR;
    }
    strcpy(userDatabase[i]->pass, pass);
    return EDIT_USER_SUCCESS;
}

bool removeUser(char *name) {
    if (name == NULL ) {
        return false;
    }
    int idx = find_user(name);
    if (idx == -1) {
        return false;
    }
    struct user *toDel = userDatabase[idx];
    userDatabase[idx] = userDatabase[nUsers - 1];

    free(toDel->name);
    free(toDel->pass);
    free(toDel);

    if (--nUsers == 0) {
        auth_required = false;
    }

    return true;
}

static enum authenticationStatus authenticate_user_general(authentication_credentials *credentials, struct user **users, uint8_t n) {
    for (int i = 0; i < n; i++) {
        if (compare_users(users[i]->name, (char *) credentials->username) &&
            compare_users(users[i]->pass, (char *) credentials->password)) {
            return AUTHENTICATION_STATUS_OK;
        }
    }
    return -1;
}

const struct user *authenticate_user(authentication_credentials *credentials) {
    for (int i = 0; i < nUsers; i++) {
        if (compare_users(userDatabase[i]->name, (char *) credentials->username) &&
            compare_users(userDatabase[i]->pass, (char *) credentials->password)) {
            return userDatabase[i];
        }
    }
    return NULL;
}

enum authenticationStatus authenticate_shoes_user(authentication_credentials *credentials) {
    return authenticate_user_general(credentials, shoesUserDatabase, snUsers);
}

struct user ** get_socks_users(uint8_t * n) {
    *n = nUsers;
    return userDatabase;
}
