#include "bindings.h"

void alias(lua_State *L) {

    static auto localL = L;

    luabridge::getGlobalNamespace(L).addFunction(
        "UnityInfo", *[]() { luaL_dostring(localL, "unity:info()"); });
}