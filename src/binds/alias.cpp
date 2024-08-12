#include "bindings.h"

BINDFUNC(alias) {
    luabridge::getGlobalNamespace(L).addFunction("UnityInfo", [&]() {
        luaL_dostring(L, "unity:info()");
    });
}