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

enum authentication_status
authenticate_shoes_user(authentication_credentials * credentials);

struct user ** get_socks_users(uint8_t * n);

bool get_auth_state();

void free_users();

void change_auth_state(bool required);

enum add_user_response {
    ADD_USER_SUCCESS,
    ADD_USER_ALREADY_EXISTS,
    ADD_USER_MAX_REACHED,
    ADD_USER_SERV_ERROR
};
enum add_user_response add_user(char * name, char * pass);
enum add_user_response add_user_shoes(char * name, char * pass);

enum edit_user_response {
    EDIT_USER_SUCCESS,
    EDIT_USER_NOT_FOUND,
    EDIT_USER_SERV_ERROR
};
enum edit_user_response edit_user(char * name, char * pass);
enum edit_user_response edit_user_shoes(char * name, char * pass);

bool remove_user(char * name);
bool remove_user_shoes(char * name);
