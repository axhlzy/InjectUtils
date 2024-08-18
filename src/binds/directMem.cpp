// todo [ direct memory access ] 封装一些内存直接访问的lua绑定方法
// 通过直接去读取 /proc/xxx/map 和 /proc/xxx/mem 来实现

#include "bindings.h"

BINDFUNC(direct_mem) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("mem")
        .addFunction("read", [](PTR start, size_t size) {})
        .addFunction("write", [](PTR start, const char *data, size_t size) {})
        // ...
        .endNamespace();
}