#pragma once
#include "authentication.h"
#include <stdbool.h>
#include "args.h"

struct users {
  const char *name;
  const char *pass;
};

const struct users *authenticate_user(authentication_credentials *credentials);

void initialize_users(struct users *users, uint8_t nusers);

bool get_auth_state();

void free_users();

void change_auth_state(bool required);
