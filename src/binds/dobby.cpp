#include "dobby.h"
#include "bindings.h"

#include <map>
#include <vector>

#include "HookManager.h"

using namespace std;

class dobby_bind {
public:
    inline static map<void *, void *> hookMap;
    inline static vector<void *> cur_list;
    inline static int count_hook_index = -1;

    static void version() {
        console->info("Dobby version: {}\n", DobbyGetVersion());
    }

    // nop
    void n(PTR ptr) {
        console->info("nop -> {:p}\n", (void *)ptr);
        HK((void *)ptr, [=](void *a, void *b, void *c, void *d) {
            console->info("Called NOPPED -> {:p}", (void *)ptr);
        });
    }

    // cancel nop
    void nn(PTR ptr) {
        console->info("cancel nop -> {:p}\n", (void *)ptr);
        UHK((void *)ptr);
    }

    // means attach
    void A(PTR ptr, const char *luaExec) {
        HK((void *)ptr, [=](void *a, void *b, void *c, void *d) {
            SrcCall((void *)ptr, a, b, c, d);
            luaL_dostring(G_LUA, luaExec);
        });
    }
};

BINDFUNC(dobby) {
    luabridge::getGlobalNamespace(L)
        .beginClass<dobby_bind>("dobby_bind")
        .addFunction("n", &dobby_bind::n)
        .addFunction("nn", &dobby_bind::nn)
        .addFunction("A", &dobby_bind::A)
        .endClass()
        .beginNamespace("dobby")
        .addFunction("version", &dobby_bind::version)
        .endNamespace();
    static auto dobby = new dobby_bind();
    luabridge::setGlobal(L, dobby, "dobby_bind");
}