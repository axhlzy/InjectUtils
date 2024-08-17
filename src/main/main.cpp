#include "main.h"
#include "cxxopts.hpp"
#include "fmt/format.h"
#include <KittyMemoryEx.hpp>
#include <stacktrace.h>
#include <utils.h>
// #include "test.h"

extern void start_local_repl();

int main(int argc, char *argv[]) {
    try {
        cxxopts::Options options(argv[0], "Inject-Utils");
        options.add_options()("h,help", "Print help")("d,debug", "Start in debug mode")("r,restart", "restart app")("c,clear", "clear app")("p,pid", "PID or package name", cxxopts::value<std::string>());

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // for debug
        // console->info("{}", getpid());
        // raise(SIGSTOP);

        if (result.count("debug") || result.count("d")) {
            JNI_OnLoad(nullptr, nullptr);
            return 0;
        }

        if (result.count("pid") || result.count("p")) {
            // set_selinux_state(false);
            init_kittyMemMgr();

            auto pid_or_package = result["pid"].as<std::string>();

            pid_t pid = -1;

            try {
                if (std::all_of(pid_or_package.begin(), pid_or_package.end(), ::isdigit)) {
                    pid = std::stoi(pid_or_package);
                    std::cout << "PID provided: " << pid << std::endl;
                    if (result.count("clear") || result.count("restart")) {
                        std::cout << "Warning: --clear or --restart options are not supported with PID" << std::endl;
                    }
                } else {
                    const auto pkg_name = pid_or_package;
                    std::cout << "Package name provided: " << pid_or_package << std::endl;
                    pid = KittyMemoryEx::getProcessID(pid_or_package);
                    std::cout << "Retrieved PID for package: " << pid << std::endl;
                }
            } catch (const std::exception &e) {
                std::cerr << "Error parsing PID or package name: " << e.what() << std::endl;
                return 1;
            }

            if (pid != -1) {
                if (kill(pid, 0) == 0) {
                    std::cout << "Process found with PID: " << pid << std::endl;
                    inject(pid);
                    start_local_repl();
                } else {
                    std::cerr << "No process found with PID: " << pid << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Failed to get PID for the given input." << std::endl;
                return 1;
            }
        }

        else {
            std::cout << options.help() << std::endl;
            return 1;
        }

    } catch (const cxxopts::exceptions::exception &e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}