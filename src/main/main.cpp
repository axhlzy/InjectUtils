#include "main.h"
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "LuaSocket/LuaReplClient.hpp"

int main(int argc, char *argv[]) {

    // checkIl2cpp();

    set_selinux_state(false);

    if (argc == 1) {
        S_TYPE = START_TYPE::DEBUG;
        JNI_OnLoad(nullptr, nullptr);
        return 0;
    }

    if (argc != 2) {
        console->error("Usage: {} <pid|package_name>", argv[0]);
        return 1;
    }

    S_TYPE = START_TYPE::SOCKET;

    pid_t pid = -1;

    try {
        if (isdigit(argv[1][0])) {
            pid = std::stoi(argv[1]);
        }
    } catch (const std::exception &e) {
        std::string appPkg = argv[1];
        // not working
        pid = KittyMemoryEx::getProcessID(appPkg);
    }

    inject(pid);

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
                client.close();
                break;
            }
            client.send_message(input, [](const std::string &response) {
                std::cout << response << std::endl;
            });
        }
    }

    return 0;
}