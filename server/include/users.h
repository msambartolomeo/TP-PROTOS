#pragma once
#include "authentication.h"
#include <stdbool.h>
#include "args.h"

enum authenticationStatus authenticate_user(authentication_credentials *credentials);

void initialize_users(struct users *users, uint8_t nusers);
