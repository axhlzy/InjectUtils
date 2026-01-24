#include "dobby.h"
#include "HookManager.h"
#include "bindings.h"

#include <map>
#include <vector>

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
        console->info("Cancel nop -> {:p}\n", (void *)ptr);
        UHK((void *)ptr);
    }

    void A(PTR ptr, const char *enterExec, const char *leaveExec) {
        if (!ptr || !enterExec || !leaveExec) {
            console->info("Invalid parameters for A function.\n");
            return;
        }

        console->info("Attach -> {:p}\n", (void *)ptr);

        lua_getglobal(G_LUA, "dobby_bind:attach");
        lua_pushlightuserdata(G_LUA, this);
        lua_pushnumber(G_LUA, (uintptr_t)ptr);
        lua_pushstring(G_LUA, enterExec);
        lua_pushstring(G_LUA, leaveExec);

        if (lua_pcall(G_LUA, 4, 1, 0) != LUA_OK) {
            console->info("Lua error: {}\n", lua_tostring(G_LUA, -1));
            lua_pop(G_LUA, 1);
        } else {
            int result = luaL_checknumber(G_LUA, -1);
            console->info("Attach result: {}\n", result);
            lua_pop(G_LUA, 1);
        }
    }

    // means attach
    int attach(PTR ptr, const char *enterExec, const char *leaveExec) {
        return HK((void *)ptr, [=](void *a, void *b, void *c, void *d) {
            luaL_dostring(G_LUA, enterExec);
            SrcCall((void *)ptr, a, b, c, d);
            luaL_dostring(G_LUA, leaveExec);
        });
    }
};

BINDFUNC(dobby) {

    luabridge::getGlobalNamespace(L)
        .beginClass<dobby_bind>("dobby_bind")
        .addFunction("n", &dobby_bind::n)
        .addFunction("nn", &dobby_bind::nn)
        .addFunction("attach", &dobby_bind::attach)
        .addFunction("A", &dobby_bind::A)
        .addStaticFunction("version", &dobby_bind::version)
        .endClass();

    static dobby_bind dobby;
    luabridge::setGlobal(L, &dobby, "dobby_bind");

    // alias
    luabridge::getGlobalNamespace(L)
        .addFunction("n", [](PTR ptr) { luaL_dostring(G_LUA, fmt::format("dobby_bind:n({:p})", ptr).c_str()); })
        .addFunction("nn", [](PTR ptr) { luaL_dostring(G_LUA, fmt::format("dobby_bind:nn({:p})", ptr).c_str()); })
        .addFunction("attach", [](PTR ptr, const char *enterExec, const char *leaveExec) { luaL_dostring(G_LUA, fmt::format("dobby_bind:A({:p}, {}, {})", ptr, enterExec, leaveExec).c_str()); })
        .addFunction("version", &dobby_bind::version)
        .addFunction("A", [](PTR ptr, const char *enterExec, const char *leaveExec) { luaL_dostring(G_LUA, fmt::format("dobby_bind:A({:p}, {}, {})", ptr, enterExec, leaveExec).c_str()); });
}