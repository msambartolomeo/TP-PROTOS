#include "users.h"
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

bool get_auth_state() { return auth_required; }

void change_auth_state(bool required) { auth_required = required; }

int compare_users(const char * one, const char * two) {
    return strcmp(one, two) == 0;
}

static int find_user(char * name, struct user ** users, uint8_t size) {
    for (int i = 0; i < size; i++) {
        if (compare_users(users[i]->name, name)) {
            return i;
        }
    }
    return -1;
}


enum add_user_response add_user_general(char * name, char * pass, struct user ** users, uint8_t * size) {
    if (*size == MAX_USERS) {
        return ADD_USER_MAX_REACHED;
    }
    if (find_user(name, users, *size) != -1) {
        return ADD_USER_ALREADY_EXISTS;
    }

    users[*size] = malloc(sizeof(struct user));
    if (users[*size] == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    size_t ulen = strlen(name);
    size_t plen = strlen(pass);
    users[*size]->name = malloc(ulen + 1);
    users[*size]->pass = malloc(plen + 1);
    if (name == NULL || pass == NULL) {
        return ADD_USER_SERV_ERROR;
    }

    strcpy(users[*size]->name, name);
    strcpy(users[*size]->pass, pass);
    *size = *size + 1;
    return ADD_USER_SUCCESS;
}

enum add_user_response add_user(char * name, char * pass) {
    enum add_user_response ret = add_user_general(name, pass, user_database, &n_users);
    if (ret == ADD_USER_SUCCESS && n_users != 0) {
        auth_required = true;
    }
    return ret;
}

enum add_user_response add_user_shoes(char * name, char * pass) {
    return add_user_general(name, pass, shoes_user_database, &sn_users);
}

enum edit_user_response edit_user_general(char * name, char * pass, struct user ** users, uint8_t * size) {
    int i = find_user(name, users, *size);
    if (i == -1) {
        return EDIT_USER_NOT_FOUND;
    }
    size_t plen = strlen(pass);
    users[i]->pass = realloc(users[i]->pass, plen + 1);
    if (users[i]->pass == NULL) {
        return EDIT_USER_SERV_ERROR;
    }
    strcpy(users[i]->pass, pass);
    return EDIT_USER_SUCCESS;
}

enum edit_user_response edit_user(char * name, char * pass) {
    return edit_user_general(name, pass, user_database, &n_users);
}

// Edit y Remove con SHOES no se usa, pero se implementa de forma general para poder extenderla.
enum edit_user_response edit_user_shoes(char * name, char * pass) {
    return edit_user_general(name, pass, shoes_user_database, &sn_users);
}

bool remove_user_general(char * name, struct user ** users, uint8_t * size) {
    if (name == NULL) {
        return false;
    }
    int idx = find_user(name, users, *size);
    if (idx == -1) {
        return false;
    }
    struct user * to_del = users[idx];
    users[idx] = users[*size - 1];

    free(to_del->name);
    free(to_del->pass);
    free(to_del);

    *size = *size - 1;
    return true;
}

bool remove_user(char * name) {
    bool res = remove_user_general(name, user_database, &n_users);
    if (res && n_users == 0) {auth_required = false;}
    return res;
}

bool remove_user_shoes(char * name) {
    return remove_user_general(name, shoes_user_database, &sn_users);
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
