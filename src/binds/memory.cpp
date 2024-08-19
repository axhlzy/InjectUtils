#include "Semaphore.hpp"
#include "bindings.h"
#include "signal_enum.h"
#include "utils.h"
#include <signal.h>
#include <vector>

namespace BIND_MEM {

    std::vector<uintptr_t> g_mem_watch_vec;
    std::mutex g_mem_watch_mutex;

    void watchMem(PTR address, size_t size) {
        std::lock_guard<std::mutex> lock(g_mem_watch_mutex);
        SET_MEM_PROTECTION___(address);
        g_mem_watch_vec.emplace_back(reinterpret_cast<uintptr_t>(address));
        console->info("ADD MEM WATCH -> {:p}", address);
    }

    void watchMem(PTR address) {
        watchMem(address, sizeof(void *));
    }

    void signalHandler(int sig, siginfo_t *info, void *context) {
        std::lock_guard<std::mutex> lock(g_mem_watch_mutex);
        auto msg = fmt::format("Caught signal {}, signal code: {}\n",
                               magic_enum::enum_name((SignalE)sig), info->si_code);
        logd("%s", msg.c_str());
        void *fault_address = info->si_addr;
        for (auto &mod_address : g_mem_watch_vec) {
            if (mod_address == reinterpret_cast<uintptr_t>(fault_address)) {
                volatile uintptr_t *p = reinterpret_cast<volatile uintptr_t *>(fault_address);
                SET_MEM_PROTECTION_RWX(fault_address);
                console->info("STOP AT -> {:p}", fault_address);
                logd("STOP AT -> %p", fault_address);
                showRegs(reinterpret_cast<ucontext_t *>(context));
                SEMAPHORE_WAIT
                return;
            }
        }
        signal(sig, SIG_DFL);
        // raise(sig);
    }

    void setupAppSignalHandler() {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = signalHandler;
        sigaction(SIGSEGV, &sa, NULL);
    }
}

BINDFUNC(memory) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("mem")
        .addFunction("watch",
                     luabridge::overload<PTR>(BIND_MEM::watchMem),
                     luabridge::overload<PTR, size_t>(BIND_MEM::watchMem))
        .endNamespace();

    luabridge::getGlobalNamespace(L)
        .addFunction("watch",
                     luabridge::overload<PTR>(BIND_MEM::watchMem),
                     luabridge::overload<PTR, size_t>(BIND_MEM::watchMem));

    BIND_MEM::setupAppSignalHandler();
}