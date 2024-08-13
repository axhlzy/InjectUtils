#include "bindings.h"
#include <signal.h>
#include <utils.h>

#include "Semaphore.hpp"

BINDFUNC(signal) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("signal")
        // int raise(int __signal);
        .addFunction("raise", [](int __signal) { return raise(__signal); })
        .addFunction("post", []() { SEMAPHORE_POST })
        .endNamespace();
}