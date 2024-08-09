#include <arpa/inet.h>
#include <iostream>
#include <jni.h>
#include <main.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "magic_enum_all.hpp"

static JavaVM *g_jvm;
static JNIEnv *env;
static std::thread *g_thread = NULL;

lua_State *G_LUA = NULL;

// #define LUA_OK		0
// #define LUA_YIELD 1
// #define LUA_ERRRUN 2
// #define LUA_ERRSYNTAX 3
// #define LUA_ERRMEM 4
// #define LUA_ERRERR 5
enum LUA_STATUS {
    LUA_OK_ = 0,
    LUA_YIELD_ = 1,
    LUA_ERRRUN_ = 2,
    LUA_ERRSYNTAX_ = 3,
    LUA_ERRMEM_ = 4,
    LUA_ERRERR_ = 5
};

static int serverSocket, clientSocket;

int l_print(lua_State *L) {
    int n = lua_gettop(L);
    lua_getglobal(L, "tostring");
    for (int i = 1; i <= n; i++) {
        const char *s;
        size_t len;
        lua_pushvalue(L, -1);
        lua_pushvalue(L, i);
        lua_call(L, 1, 1);
        s = lua_tolstring(L, -1, &len);
        if (s == nullptr) {
            return luaL_error(L, "'tostring' must return a string to 'print'");
        }
        if (i > 1) {
            write(clientSocket, "\t", 1);
        }
        write(clientSocket, s, len);
        lua_pop(L, 1);
    }
    write(clientSocket, "\n", 1);
    return 0;
}

void repl_socket(lua_State *L, int port = SOCKET_PORT) {

    int opt = 1;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)};

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        console->error("create socket fail");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        console->error("setsockopt fail");
        exit(EXIT_FAILURE);
    }

    if (bind(serverSocket, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) < 0) {
        console->error("serverSocket bind fail");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 3) < 0) {
        console->error("serverSocket listen fail");
        exit(EXIT_FAILURE);
    }

    if ((clientSocket = accept(serverSocket, reinterpret_cast<struct sockaddr *>(&address), &addrlen)) < 0) {
        console->error("clientSocket accept fail");
        exit(EXIT_FAILURE);
    } else {
        console->info("Client connected. IP: {}", inet_ntoa(address.sin_addr));

        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        if (getpeername(clientSocket, reinterpret_cast<struct sockaddr *>(&clientAddr), &clientAddrLen) < 0) {
            console->error("getpeername fail");
        } else {
            console->warn("Client IP: {}", inet_ntoa(clientAddr.sin_addr));
            console->warn("Client sin_family: {}", clientAddr.sin_family);
            console->warn("Client port: {}", ntohs(clientAddr.sin_port));
        }
    }

    lua_pushcfunction(L, l_print);
    lua_setglobal(L, "print");

    char buffer[1024] = {0};
    int valread;
    std::string input;
    dup2(clientSocket, STDOUT_FILENO);
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        fflush(stdout);
        valread = read(clientSocket, buffer, sizeof(buffer));
        if (valread == 0) {
            std::cout << "Client disconnected." << std::endl;
            break;
        } else if (valread == -1) {
            perror("read");
            break;
        } else {
            input = buffer;
            if (input == "exit" || input == "q") {
                write(clientSocket, "Client requested exit. \n", 24);
                close(clientSocket);
                close(serverSocket);
                break;
            }
            int status = luaL_dostring(L, input.c_str());
            if (status != LUA_OK) {
                auto msg = lua_tostring(L, -1);
                lua_writestringerror("%s\n", msg);
                write(clientSocket, msg, strlen(msg));
                lua_pop(L, 1);
            } else {
                auto status_enum = reinterpret_cast<LUA_STATUS &>(status);
                auto status_name = magic_enum::enum_name<LUA_STATUS>(status_enum);
                std::string status = std::string(status_name.substr(0, status_name.size() - 1)) + "\n";
                write(clientSocket, status.c_str(), status_name.size());
            }
        }
    }
}

static void repl(lua_State *L) {
    std::string input;
    while (true) {
        std::cout << "exec > ";
        if (std::getline(std::cin, input) && (input == "exit" || input == "q"))
            break;
        int status = luaL_dostring(L, input.c_str());
        auto status_enum = reinterpret_cast<LUA_STATUS &>(status);
        auto status_name = magic_enum::enum_name<LUA_STATUS>(status_enum);
        if (status != LUA_OK) {
            const char *msg = lua_tostring(L, -1);
            lua_writestringerror("%s\n", msg);
            lua_pop(L, 1);
        }
    }
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    if (vm == nullptr && reserved == nullptr) {
        startLuaVM();
    } else {
        S_TYPE = START_TYPE::SOCKET;
        logd("------------------- JNI_OnLoad -------------------");
        if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_OK) {
            logd("[*] GetEnv OK | env:%p | vm:%p", env, vm);
        }
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            logd("[*] AttachCurrentThread OK");
        }
        g_jvm = vm;

        g_thread = new std::thread([]() {
            startLuaVM();
        });
        g_thread->detach();
    }
    return JNI_VERSION_1_6;
}

inline void startRepl(lua_State *L) {
    if (S_TYPE == START_TYPE::DEBUG) {
        logd("[*] startRepl Debug Mode\n");
        repl(L);
    } else if (S_TYPE == START_TYPE::SOCKET) {
        logd("[*] startRepl Socket Mode\n");
        repl_socket(L, SOCKET_PORT);
    }
}

KittyMemoryMgr kittyMemMgr;
inline void init_kittyMemMgr() {
    if (!kittyMemMgr.initialize(getpid(), EK_MEM_OP_IO, true)) {
        loge("KittyMemoryMgr initialize Error occurred )':");
        console->info("KittyMemoryMgr initialize Error occurred )':");
        return;
    }
}

#define USE_SIGNAL 0

#include <setjmp.h>
static jmp_buf recover;
static void *sp = nullptr;
static struct sigaction sa;

void reg_crash_handler() {

#if USE_SIGNAL
    static sighandler_t segfault_handler = *[](int signum) {
        loge("[-] Caught signal | signum : %d \n", signum);
        console->error("Caught signal | signum : {}", signum);
        signal(SIGSEGV, segfault_handler);
        longjmp(recover, 1);
    };
    signal(SIGSEGV, segfault_handler);
#else
    static auto signal_handler = [](int signum, siginfo_t *info, void *context) {
        loge("[-] Caught signal | signum : %d | siginfo_t : %p | context : %p\n", signum, info->si_addr, context);
        console->error("Caught signal | signum : {} | siginfo_t : {} | context : {}", signum, info->si_addr, context);
        // extract register values
        ucontext_t *ucontext = (ucontext_t *)context;
        // fault_address
        loge("[-] fault_address: %p\n", ucontext->uc_mcontext.fault_address);
#ifdef __aarch64__
        loge("[-] x0: %p | x1: %p | x2: %p | x3: %p | x4: %p | x5: %p | x6: %p | x7: %p | x8: %p | x9: %p | x10: %p | x11: %p | x12: %p | sp: %p | lr: %p | pc: %p\n",
             ucontext->uc_mcontext.regs[0], ucontext->uc_mcontext.regs[1], ucontext->uc_mcontext.regs[2], ucontext->uc_mcontext.regs[3],
             ucontext->uc_mcontext.regs[4], ucontext->uc_mcontext.regs[5], ucontext->uc_mcontext.regs[6], ucontext->uc_mcontext.regs[7],
             ucontext->uc_mcontext.regs[8], ucontext->uc_mcontext.regs[9], ucontext->uc_mcontext.regs[10], ucontext->uc_mcontext.regs[11],
             ucontext->uc_mcontext.regs[12], ucontext->uc_mcontext.sp, ucontext->uc_mcontext.regs[30], ucontext->uc_mcontext.pc);
#elif __arm__
        loge("[-] r0: %p | r1: %p | r2: %p | r3: %p | r4: %p | r5: %p | r6: %p | r7: %p | r8: %p | r9: %p | r10: %p | r11: %p | r12: %p | sp: %p | lr: %p | pc: %p\n",
             ucontext->uc_mcontext.arm_r0, ucontext->uc_mcontext.arm_r1, ucontext->uc_mcontext.arm_r2, ucontext->uc_mcontext.arm_r3,
             ucontext->uc_mcontext.arm_r4, ucontext->uc_mcontext.arm_r5, ucontext->uc_mcontext.arm_r6, ucontext->uc_mcontext.arm_r7,
             ucontext->uc_mcontext.arm_r8, ucontext->uc_mcontext.arm_r9, ucontext->uc_mcontext.arm_r10, ucontext->uc_mcontext.arm_fp,
             ucontext->uc_mcontext.arm_ip, ucontext->uc_mcontext.arm_sp, ucontext->uc_mcontext.arm_lr, ucontext->uc_mcontext.arm_pc);
#endif
        sigaction(SIGSEGV, &sa, nullptr);
        longjmp(recover, 1);
    };
    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
#endif

    if (setjmp(recover) == 0) {
        logd("[*] Lua VM started\n"); // android_logcat
        // get current sp ptr
        asm volatile("mov %0, sp" : "=r"(sp));
        console->info("Lua VM started | sp: {}", sp);
    } else {
        loge("[-] Lua VM crashed and restart now\n");
        console->error("Lua VM crashed and restart now | sp: {}", sp);
        // set sp
        asm volatile("mov sp, %0" : : "r"(sp));
        // set lr = initVM
        asm volatile("mov lr, %0" : : "r"((void *)initVM));
#ifdef __aarch64__
        asm volatile("ret");
#elif __arm__
        asm volatile("bx lr");
#endif
    }
}

void initVM() {

    init_kittyMemMgr();

    lua_State *L = luaL_newstate();

    G_LUA = std::ref(L);

    luaL_openlibs(L);

    bind_libs(L);

    startRepl(L);

    // test(L);

    lua_close(L);
}

#include "linker_soinfo.h"
void startLuaVM() {

    reg_crash_handler();

    initVM();
}