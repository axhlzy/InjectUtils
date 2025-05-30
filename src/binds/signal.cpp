#include "Semaphore.hpp"
#include "bindings.h"
#include <signal.h>
#include <utils.h>
#include <vector>

BINDFUNC(signal) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("signal")
        // int raise(int __signal);
        .addFunction("raise", [](int __signal) { return raise(__signal); })
        .addFunction("post", []() { SEMAPHORE_POST })
        .endNamespace();

    // alias
    luabridge::getGlobalNamespace(L)
        .addFunction("raise", [](int __signal) { return raise(__signal); })
        .addFunction("cont", []() { luaL_dostring(G_LUA, "signal.post()"); });
}