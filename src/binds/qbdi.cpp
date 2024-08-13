#include "bindings.h"

BINDFUNC(qbdi) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("qbdi")
        .endNamespace();
}