#pragma once
#include "authentication.h"
#include <stdbool.h>
#include "args.h"

enum authenticationStatus authenticate_user(authentication_credentials *credentials);

void initialize_users(struct users *users, uint8_t nusers);

void initialize_shoes_users(struct users *users, uint8_t nusers);

enum authenticationStatus authenticate_shoes_user(authentication_credentials *credentials);

struct users * get_socks_users(uint8_t * n);

