#include "bindings.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>

void findClass_b(const char *classNameFilter) {
  throw std::runtime_error("not implemented");
}

void findMethod_b(const char *classNameFilter, const char *methodNameFilter) {
  throw std::runtime_error("not implemented");
}

void hookClass_b(const char *className) {
  throw std::runtime_error("not implemented");
}

void unHookClass_b(const char *className) {
  throw std::runtime_error("not implemented");
}

void hookMethod_b(const char *className, const char *methodName) {
  throw std::runtime_error("not implemented");
}

BINDFUNC(javahook) {

  luabridge::getGlobalNamespace(L)
      .beginNamespace("javahook")
      .addFunction("findClass", luabridge::overload<const char *>(findClass_b))
      .addFunction(
          "findMethod",
          luabridge::overload<const char *, const char *>(findMethod_b))
      .addFunction("hookClass", luabridge::overload<const char *>(hookClass_b))
      .addFunction("unHookClass",
                   luabridge::overload<const char *>(unHookClass_b))
      .addFunction(
          "hookMethod",
          luabridge::overload<const char *, const char *>(hookMethod_b))
      .endNamespace();
}