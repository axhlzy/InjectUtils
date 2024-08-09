#include "main.h"
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

KittyInjector kitInjector;
std::chrono::duration<double, std::milli> inj_ms{};

void checkIl2cpp() {
    std::function<bool()> const static checkIl2cppLoaded = []() -> bool {
        void *handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
        if (handle != nullptr) {
            return true;
        } else {
            return false;
        };
    };

    static std::thread t([]() {
        pthread_setname_np(pthread_self(), "dohook");
        while (true) {
            if (checkIl2cppLoaded())
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    t.detach();
}

int inject(pid_t pid) {
    string lib = get_self_path();
    bool use_memfd = false, hide_maps = false, hide_solist = false, stopped = false;

    injected_info_t ret{};
    if (kitInjector.init(pid, EK_MEM_OP_IO)) {
        console->info("KittyInjector init");
        if (kitInjector.attach()) {
            console->info("KittyInjector attach");
        } else {
            console->error("KittyInjector attach failed");
            return -1;
        }
        auto tm_start = std::chrono::high_resolution_clock::now();

        ret = kitInjector.injectLibrary(lib, RTLD_NOW | RTLD_LOCAL, use_memfd, hide_maps, hide_solist,
                                        [&pid, &stopped](injected_info_t &injected) {
                                            if (injected.is_valid() && stopped) {
                                                console->info("[*] Continuing target process...");
                                                kill(pid, SIGCONT);
                                                stopped = false;
                                            }
                                        });

        inj_ms = std::chrono::high_resolution_clock::now() - tm_start;
        if (inj_ms.count() > 0)
            console->info("[*] Injection took {} MS.", inj_ms.count());

        kitInjector.detach();
    }

    return 0;
}

void startLocalRepl(int port = SOCKET_PORT) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        console->error("Error creating socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        console->error("Error connecting to socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    console->info("Connected to socket on port {}", port);

    constexpr int BFSIZE = 0x1000;
    char buffer[BFSIZE] = {0};
    while (true) {
        fflush(stdout);
        memset(buffer, 0, sizeof(buffer));
        std::cout << "exec > ";
        std::cin.getline(buffer, BFSIZE);

        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "q") == 0) {
            console->info("Exiting...");
            break;
        }
        console->error("1 -> {} {}", (char *)buffer, strlen(buffer));

        int n = write(sockfd, buffer, strlen(buffer));
        if (n < 0) {
            console->error("Error writing to socket");
            break;
        }

        std::cout << std::flush;
        memset(buffer, 0, BFSIZE);

        n = read(sockfd, buffer, BFSIZE);
        if (n < 0) {
            console->error("Error reading from socket");
            break;
        }

        console->info("{}", buffer);
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {

    // checkIl2cpp();

    // set_selinux_state
    int result = system("setenforce 0");
    if (result == -1) {
        console->error("Error executing system command.");
    } else {
        console->warn("setenforce 0 executed successfully.");
    }

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

    if (inject(pid) == -1)
        return -1;

    if (S_TYPE == START_TYPE::SOCKET) {
        startLocalRepl();
    }

    return 0;
}