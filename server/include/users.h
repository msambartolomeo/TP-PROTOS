#pragma once
#include "authentication.h"
#include <stdbool.h>
#include "args.h"

struct users {
  char *name;
  char *pass;
};

enum authenticationStatus authenticate_user(authentication_credentials *credentials);

void initialize_users(struct users *users, uint8_t nusers);

bool get_auth_state();

void change_auth_state(bool required);
