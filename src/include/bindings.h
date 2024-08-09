#ifndef MAIN_BINDS_H
#define MAIN_BINDS_H

#include "main.h"

void bind_libs(lua_State *L);

void reg_base(lua_State *L);

void reg_global(lua_State *L);

void reg_xdl(lua_State *L);

void reg_dobby(lua_State *L);

void reg_unity(lua_State *L);

// bind for UnityResolve : NOT TEST
void reg_UnityResolve(lua_State *L);

void reg_lief(lua_State *L);

void alias(lua_State *L);

void reg_oai(lua_State *L);

void reg_asm(lua_State *L);

#endif