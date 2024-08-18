#include "Semaphore.hpp"
#include "bindings.h"
#include "signal_enum.h"
#include <signal.h>
#include <utils.h>
#include <vector>

std::vector<uintptr_t> g_addr_mod_vec;
std::mutex mod_vec_mutex;

void XORINS(void *address) {
    std::lock_guard<std::mutex> lock(mod_vec_mutex);
    g_addr_mod_vec.emplace_back(reinterpret_cast<uintptr_t>(address));
    SET_MEM_PROTECTION(address);
    volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(address);
    *p ^= (uintptr_t)address;
}

__attribute__((noinline)) void XORINS(PTR address) {
    console->info("ADD BP -> {:p}", address);
    XORINS(reinterpret_cast<void *>(address));
}

void signalHandler(int sig, siginfo_t *info, void *context) {
    std::lock_guard<std::mutex> lock(mod_vec_mutex);
    auto msg = fmt::format("Caught signal {}, signal code: {}\n",
                           magic_enum::enum_name((SignalE)sig), info->si_code);
    logd("%s", msg.c_str());
    void *fault_address = info->si_addr;
    for (auto &mod_address : g_addr_mod_vec) {
        if (mod_address == reinterpret_cast<uintptr_t>(fault_address)) {
            volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(fault_address);
            *p ^= (uintptr_t)fault_address;
            console->info("STOP AT -> {:p}", fault_address);
            logd("STOP AT -> %p", fault_address);
            // luaL_dostring(G_LUA, fmt::format("xdl.xdl_showAddress({:p})", fault_address).c_str());
            luaL_dostring(G_LUA, fmt::format("asm.cs({:p})", fault_address).c_str());
            showRegs(reinterpret_cast<ucontext_t *>(context));
            SEMAPHORE_WAIT
            return;
        }
    }
    // signal(sig, SIG_DFL);
    raise(sig);
}

void setupAppSignalHandler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = signalHandler;
    sigaction(SIGILL, &sa, NULL);
}

void breakWithSymbol(const char *symbol) {
    lua_getglobal(G_LUA, "sym");
    lua_getfield(G_LUA, -1, "find");
    lua_pushstring(G_LUA, symbol);

    if (lua_pcall(G_LUA, 1, 1, 0) != LUA_OK) {
        console->info("Lua error: {}\n", lua_tostring(G_LUA, -1));
        lua_pop(G_LUA, 1);
        return;
    }

    void *address = lua_touserdata(G_LUA, -1);
    lua_pop(G_LUA, 1);

    if (!address) {
        console->info("Symbol not found: {}\n", symbol);
        return;
    }

    XORINS((PTR)address);
}

void breakWithSymbol(const char *mdName, const char *symbol) {
    lua_getglobal(G_LUA, "sym");
    lua_getfield(G_LUA, -1, "find");
    lua_pushstring(G_LUA, mdName);
    lua_pushstring(G_LUA, symbol);

    if (lua_pcall(G_LUA, 2, 1, 0) != LUA_OK) {
        console->info("Lua error: {}\n", lua_tostring(G_LUA, -1));
        lua_pop(G_LUA, 1);
        return;
    }

    void *address = lua_touserdata(G_LUA, -1);
    lua_pop(G_LUA, 1);

    if (!address) {
        console->info("Symbol not found: {}\n", symbol);
        return;
    }

    XORINS((PTR)address);
}

BINDFUNC(breakpoint) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("bp")
        .addFunction("b",
                     luabridge::overload<PTR>(XORINS),
                     luabridge::overload<void *>(XORINS),
                     luabridge::overload<const char *>(breakWithSymbol),
                     luabridge::overload<const char *, const char *>(breakWithSymbol))
        .addFunction("setupAppSignalHandler", setupAppSignalHandler)
        .endNamespace();

    // alias
    luabridge::getGlobalNamespace(L)
        .addFunction("b",
                     luabridge::overload<PTR>(XORINS),
                     luabridge::overload<void *>(XORINS),
                     luabridge::overload<const char *>(breakWithSymbol),
                     luabridge::overload<const char *, const char *>(breakWithSymbol))
        .addFunction("setupAppSignalHandler", setupAppSignalHandler);

    setupAppSignalHandler();
}