#ifndef MAIN_BINDS_H
#define MAIN_BINDS_H

#include "main.h"

#define BINDFUNC(name) extern "C" void reg_##name##__(lua_State *L)

void bind_libs(lua_State *L);

#endif