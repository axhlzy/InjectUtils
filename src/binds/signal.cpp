#include "bindings.h"
#include <signal.h>

BINDFUNC(signal) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("signal")
        .addFunction("raise", [](int __signal) {
            // int raise(int __signal);
            return raise(__signal);
        })
        .endNamespace();
}