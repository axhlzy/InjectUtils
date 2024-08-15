#include "Semaphore.hpp"
#include "bindings.h"
#include <signal.h>
#include <utils.h>
#include <vector>

const int xor_value = 0x2323;
static std::vector<uintptr_t> g_addr_mod_vec;
static std::mutex mod_vec_mutex;

void XORINS(void *address) {
    std::lock_guard<std::mutex> lock(mod_vec_mutex);
    g_addr_mod_vec.emplace_back(reinterpret_cast<uintptr_t>(address));
    SET_MEM_PROTECTION(address);
    volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(address);
    uintptr_t original = *p;
    uintptr_t modification = original ^ xor_value;
    *p = modification;
}

void signalHandler(int sig, siginfo_t *info, void *unused) {
    std::lock_guard<std::mutex> lock(mod_vec_mutex);
    std::cerr << "Caught illegal instruction signal (SIGILL), signal code: " << sig << std::endl;
    void *fault_address = info->si_addr;
    for (auto &mod_address : g_addr_mod_vec) {
        if (mod_address == reinterpret_cast<uintptr_t>(fault_address)) {
            volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(fault_address);
            uintptr_t current = *p;
            uintptr_t original = current ^ xor_value;
            *p = original;
            SEMAPHORE_POST
            return;
        }
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

void setupAppSignalHandler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = signalHandler;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
}

BINDFUNC(breakpoint) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("bp")
        .addFunction("b", [](PTR address) { XORINS(reinterpret_cast<void *>(address)); })
        .addFunction("setupAppSignalHandler", setupAppSignalHandler)
        .endNamespace();

    luaL_dostring(L, "bp.setupAppSignalHandler()");
}