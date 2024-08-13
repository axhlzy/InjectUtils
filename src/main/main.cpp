#include "main.h"
#include "LuaSocket/LuaReplClient.hpp"
#include "cxxopts.hpp"
// #include "test.h"

int main(int argc, char *argv[]) {
    try {
        cxxopts::Options options(argv[0], "Inject-Utils");
        options.add_options()("h,help", "Print help")("d,debug", "Start in debug mode")("p,pid", "PID or package name",
                                                                                        cxxopts::value<std::string>());

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("debug")) {
            S_TYPE = START_TYPE::DEBUG;
            JNI_OnLoad(nullptr, nullptr);
            return 0;
        }

        if (result.count("pid")) {
            S_TYPE = START_TYPE::SOCKET;
            set_selinux_state(false);

            auto pid_or_package = result["pid"].as<std::string>();

            pid_t pid = -1;

            try {
                if (std::all_of(pid_or_package.begin(), pid_or_package.end(), ::isdigit)) {
                    pid = std::stoi(pid_or_package);
                    std::cout << "PID provided: " << pid << std::endl;
                } else {
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
                    inject(pid);
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

    // start local lua repl
    if (S_TYPE == START_TYPE::SOCKET) {

        LuaReplClient client(std::to_string(SOCKET_PORT));

        client.connect();

        std::string input;
        while (true) {
            std::cout << "exec > ";
            std::getline(std::cin, input);
            if (input.empty())
                continue;
            if (input == "exit" || input == "q") {
                client.close_connect();
                break;
            }
            client.send_message(input, [](const std::string &response) {
                std::cout << "\n"
                          << response << std::endl;
            });
        }
    }

    return 0;
}