#include "bindings.h"
#include "log.h"

#include <fstream>
#include <string>
#include <unistd.h>

inline std::string getCmdline(pid_t pid) {
    std::ifstream cmdlineFile("/proc/" + std::to_string(pid) + "/cmdline");
    std::string cmdline;

    if (cmdlineFile.is_open()) {
        std::getline(cmdlineFile, cmdline);
        cmdlineFile.close();
    }

    return cmdline;
}

BINDFUNC(process) {

    luabridge::getGlobalNamespace(L)
        .addFunction("getpid", []() { console->info("{} [ {} ] | {}", getpid(), getThreadName(getpid()), getCmdline(getpid())); })
        .addFunction("getppid", []() { console->info("{} [ {} ] | {}", getppid(), getThreadName(getppid()), getCmdline(getppid())); })
        .addFunction("gettid", []() { console->info("{} [ {} ] | {}", gettid(), getThreadName(gettid()), getCmdline(gettid())); })
        .addFunction("getgid", []() { console->info("{}", getgid()); })
        .addFunction("geteuid", []() { console->info("{}", geteuid()); })
        .addFunction("getuid", []() { console->info("{}", getuid()); })
        .addFunction("getpagesize", []() { console->info("{}", getpagesize()); })
        .addFunction("getcwd", []() {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                console->info("{}", cwd);
            } else {
                console->info("Error getting current working directory");
            }
        })
        .addFunction("now", []() {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::ostringstream oss;
            oss << std::ctime(&now_c);
            console->info("{}", oss.str());
        });
}