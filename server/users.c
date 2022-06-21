#include "users.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct user * user_database[MAX_USERS];
static uint8_t n_users;
static struct user * shoes_user_database[MAX_SHOES_USERS];
static uint8_t sn_users;
static bool auth_required = false;

void free_users() {
    for (uint8_t i = 0; i < n_users; i++) {
        free(user_database[i]->name);
        free(user_database[i]->pass);
        free(user_database[i]);
    }
    n_users = 0;
    auth_required = false;
}

void initialize_shoes_users(struct user * users, uint8_t nusers) {
    *shoes_user_database = users;
    sn_users = nusers;
}

bool get_auth_state() { return auth_required; }

void change_auth_state(bool required) { auth_required = required; }

int compare_users(const char * one, const char * two) {
    return strcmp(one, two) == 0;
}

static int find_user(char * name) {
    for (int i = 0; i < n_users; i++) {
        if (compare_users(user_database[i]->name, name)) {
            return i;
        }
    }
    return -1;
}

// TODO replace bool with status enum
enum add_user_response add_user(char * name, char * pass) {
    if (n_users == MAX_USERS) {
        return ADD_USER_MAX_REACHED;
    }
    if (find_user(name) != -1) {
        return ADD_USER_ALREADY_EXISTS;
    }

    user_database[n_users] = malloc(sizeof(struct user));
    if (user_database[n_users] == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    size_t ulen = strlen(name);
    size_t plen = strlen(pass);
    user_database[n_users]->name = malloc(ulen + 1);
    user_database[n_users]->pass = malloc(plen + 1);
    if (name == NULL || pass == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    strcpy(user_database[n_users]->name, name);
    strcpy(user_database[n_users]->pass, pass);
    if (n_users == 0) {
        auth_required = true;
    }
    n_users++;
    return ADD_USER_SUCCESS;
}

enum edit_user_response edit_user(char * name, char * pass) {
    int i = find_user(name);
    if (i == -1) {
        return EDIT_USER_NOT_FOUND;
    }
    size_t plen = strlen(pass);
    user_database[i]->pass = realloc(user_database[i]->pass, plen + 1);
    if (user_database[i]->pass == NULL) {
        return EDIT_USER_SERV_ERROR;
    }
    strcpy(user_database[i]->pass, pass);
    return EDIT_USER_SUCCESS;
}

bool remove_user(char * name) {
    if (name == NULL) {
        return false;
    }
    int idx = find_user(name);
    if (idx == -1) {
        return false;
    }
    struct user * to_del = user_database[idx];
    user_database[idx] = user_database[n_users - 1];

    free(to_del->name);
    free(to_del->pass);
    free(to_del);

    if (--n_users == 0) {
        auth_required = false;
    }

    return true;
}

static enum authentication_status
authenticate_user_general(authentication_credentials * credentials,
                          struct user ** users, uint8_t n) {
    for (int i = 0; i < n; i++) {
        if (compare_users(users[i]->name, (char *)credentials->username) &&
            compare_users(users[i]->pass, (char *)credentials->password)) {
            return AUTHENTICATION_STATUS_OK;
        }
    }
    return -1;
}

const struct user *
authenticate_user(authentication_credentials * credentials) {
    for (int i = 0; i < n_users; i++) {
        if (compare_users(user_database[i]->name,
                          (char *)credentials->username) &&
            compare_users(user_database[i]->pass,
                          (char *)credentials->password)) {
            return user_database[i];
        }
    }
    return NULL;
}

enum authentication_status
authenticate_shoes_user(authentication_credentials * credentials) {
    return authenticate_user_general(credentials, shoes_user_database,
                                     sn_users);
}

struct user ** get_socks_users(uint8_t * n) {
    *n = n_users;
    return user_database;
}
