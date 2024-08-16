#include "Semaphore.hpp"
#include "bindings.h"
#include "signal_enum.h"
#include <signal.h>
#include <utils.h>
#include <vector>

std::vector<uintptr_t> g_addr_mod_vec;
std::mutex mod_vec_mutex;
sem_t bp_sem;

void XORINS(void *address) {
    std::lock_guard<std::mutex> lock(mod_vec_mutex);
    g_addr_mod_vec.emplace_back(reinterpret_cast<uintptr_t>(address));
    SET_MEM_PROTECTION(address);
    volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(address);
    *p ^= (uintptr_t)address;
}

void signalHandler(int sig, siginfo_t *info, void *unused) {
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
            // todo disassemble (fault_address)
            sem_wait(&bp_sem);
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
    // sigaction(SIGSEGV, &sa, NULL);
    sem_init(&bp_sem, 1, 0);
}

BINDFUNC(breakpoint) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("bp")
        .addFunction("b", [](PTR address) { XORINS(reinterpret_cast<void *>(address)); })
        .addFunction("c", []() { sem_post(&bp_sem); })
        .addFunction("setupAppSignalHandler", setupAppSignalHandler)
        .endNamespace();

    setupAppSignalHandler();
}