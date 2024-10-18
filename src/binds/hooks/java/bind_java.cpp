#include "bindings.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>

void findClass(const char *classNameFilter) {
    throw new runtime_error("not implemented");
}

void findMethod(const char *classNameFilter, const char *methodNameFilter) {
    throw new runtime_error("not implemented");
}

void hookClass(const char *className) {
    throw new runtime_error("not implemented");
}

void unHookClass(const char *className) {
    throw new runtime_error("not implemented");
}

void hookMethod(const char *className, const char *methodName) {
    throw new runtime_error("not implemented");
}

BINDFUNC(javahook) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("javahook")
        .addFunction("findClass", luabridge::overload<const char *>(findClass))
        .addFunction("findMethod", luabridge::overload<const char *, const char *>(findMethod))
        .addFunction("hookClass", luabridge::overload<const char *>(hookClass))
        .addFunction("unHookClass", luabridge::overload<const char *>(unHookClass))
        .addFunction("hookMethod", luabridge::overload<const char *, const char *>(hookMethod))
        .endNamespace();
}