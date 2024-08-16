#include "bindings.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>

void *findSymbol(const char *symbol) {
    void *address = dlsym(RTLD_DEFAULT, symbol);
    if (!address) {
        console->info("Symbol not found: {}", symbol);
        return nullptr;
    }
    console->info("Symbol found: {} | {:p}", symbol, address);
    return address;
}

void *findSymbol(const char *mdName, const char *symbol) {
    auto handle = xdl_open(mdName, XDL_DEFAULT);
    if (!handle) {
        console->info("Module not found: {}", mdName);
        return nullptr;
    }
    console->info("Module found: {} | {:p}", mdName, handle);
    void *address = xdl_sym(handle, symbol, NULL);
    if (!address) {
        address = xdl_dsym(handle, symbol, NULL);
    }
    if (!address) {
        console->info("Symbol not found: {}", symbol);
        return nullptr;
    }
    console->info("Symbol found: {} | {:p}", symbol, address);
    return address;
}

BINDFUNC(sym) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("sym")
        .addFunction("find",
                     luabridge::overload<const char *>(findSymbol),
                     luabridge::overload<const char *, const char *>(findSymbol))
        .endNamespace();

    // alias
    luabridge::getGlobalNamespace(L)
        .addFunction("findSym",
                     luabridge::overload<const char *>(findSymbol),
                     luabridge::overload<const char *, const char *>(findSymbol));
}