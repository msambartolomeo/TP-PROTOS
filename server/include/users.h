#pragma once
#include "args.h"
#include "authentication.h"
#include <stdbool.h>

#define MAX_USERS 10
#define MAX_SHOES_USERS 10

struct user {
    char * name;
    char * pass;
};

const struct user * authenticate_user(authentication_credentials * credentials);

void initialize_shoes_users(struct user * users, uint8_t nusers);

enum authenticationStatus
authenticate_shoes_user(authentication_credentials * credentials);

struct user ** get_socks_users(uint8_t * n);

bool get_auth_state();

void free_users();

void change_auth_state(bool required);

enum addUserResponse {
    ADD_USER_SUCCESS,
    ADD_USER_ALREADY_EXISTS,
    ADD_USER_MAX_REACHED,
    ADD_USER_SERV_ERROR
};
enum addUserResponse addUser(char * name, char * pass);

enum editUserResponse {
    EDIT_USER_SUCCESS,
    EDIT_USER_NOT_FOUND,
    EDIT_USER_SERV_ERROR
};
enum editUserResponse editUser(char * name, char * pass);

bool removeUser(char * name);
