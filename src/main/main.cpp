#include "main.h"
#include "cxxopts.hpp"
#include "fmt/format.h"
#include "repl_manager.h"
#include <KittyMemoryEx.hpp>
#include <stacktrace.h>
#include <utils.h>

static void printUsage(const cxxopts::Options &options) {
    std::cout << options.help() << std::endl;
}

static pid_t getPidFromInput(const std::string &input) {
    // 如果是纯数字，直接作为 PID
    if (std::all_of(input.begin(), input.end(), ::isdigit)) {
        return std::stoi(input);
    }
    
    // 否则作为包名查找 PID
    pid_t pid = KittyMemoryEx::getProcessID(input);
    if (pid == 0) {
        throw std::runtime_error(
            fmt::format("Failed to get PID for package: {}", input));
    }
    
    std::cout << "Retrieved PID for package '" << input << "': " << pid << std::endl;
    return pid;
}

static bool isProcessRunning(pid_t pid) {
    if (kill(pid, SIG_BLOCK) == 0) {
        std::cout << "Process found with PID: " << pid << std::endl;
        return true;
    }
    
    std::cerr << "No process found with PID: " << pid << std::endl;
    return false;
}

static int handleDebugMode() {
    JNI_OnLoad(nullptr, nullptr);
    return 0;
}

static int handleInjectMode(const std::string &pidOrPackage) {
    init_kittyMemMgr();
    
    try {
        pid_t pid = getPidFromInput(pidOrPackage);
        
        if (!isProcessRunning(pid)) {
            return 1;
        }
        
        inject(pid);
        startReplClient();
        
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    try {
        cxxopts::Options options(argv[0], "Inject-Utils");
        options.add_options()
            ("h,help", "Print help")
            ("d,debug", "Start in debug mode")
            ("r,restart", "Restart app")
            ("c,clear", "Clear app")
            ("p,pid", "PID or package name", cxxopts::value<std::string>());

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            printUsage(options);
            return 0;
        }

        if (result.count("debug")) {
            return handleDebugMode();
        }

        if (result.count("pid")) {
            std::string pidOrPackage = result["pid"].as<std::string>();
            return handleInjectMode(pidOrPackage);
        }

        printUsage(options);
        return 1;

    } catch (const cxxopts::exceptions::exception &e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}