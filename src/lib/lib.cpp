#include "Injector/KittyInjector.hpp"
#include "KittyMemoryMgr.hpp"

extern KittyInjector kitInjector;
extern KittyMemoryMgr kittyMemMgr;

#include <main.h>
static JavaVM *g_jvm;
static JNIEnv *env;
static std::thread *g_thread = NULL;

lua_State *G_LUA = NULL;

#include <LuaSocket/LuaReplServer.hpp>
void repl_socket(lua_State *L) {
    logd("[*] start lua repl | Socket Mode | %d", SOCKET_PORT);
    try {
        boost::asio::io_context io_context;
        LuaReplServer server(io_context, SOCKET_PORT, L);
        io_context.run();
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
    }
}

void repl(lua_State *L) {
    logd("[*] start lua repl | Debug Mode");
    std::string input;
    while (true) {
        std::cout << "exec > ";
        if (std::getline(std::cin, input) && (input == "exit" || input == "q"))
            break;
        if (input.empty())
            continue;
        int status = luaL_dostring(L, input.c_str());
        if (reinterpret_cast<LUA_STATUS &>(status) != LUA_STATUS::LUA_OK_) {
            const char *msg = lua_tostring(L, -1);
            lua_writestringerror("%s\n", msg);
            lua_pop(L, 1);
        }
    }
}

#include "Semaphore.hpp"

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {

    logd("[+] CURRENT -> %d | %s", getpid(), KittyMemoryEx::getProcessName(getpid()).c_str());

    setupAppSignalHandler();

    g_thread = new std::thread([]() {
        pthread_setname_np(pthread_self(), EXEC_NAME);
        init_kittyMemMgr();
        startLuaVM();
    });

    if (vm != nullptr) {
        S_TYPE = START_TYPE::SOCKET;
        logd("------------------- JNI_OnLoad -------------------");
        if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_OK) {
            logd("[*] GetEnv OK | env:%p | vm:%p", env, vm);
        }
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            logd("[*] AttachCurrentThread OK");
        }
        g_jvm = vm;
    } else {
        if (g_thread->joinable())
            g_thread->join();
    }
    return JNI_VERSION_1_6;
}

inline void startRepl(lua_State *L) {
    if (S_TYPE == START_TYPE::DEBUG) {
        repl(L);
    } else if (S_TYPE == START_TYPE::SOCKET) {
        repl_socket(L);
    }
}

void initVM() {

    lua_State *L = luaL_newstate();

    G_LUA = std::ref(L);

    luaL_openlibs(L);

    bind_libs(L);

    startRepl(L);

    // test(L);

    lua_close(L);
}

void startLuaVM() {

    reg_crash_handler();

    initVM();
}

#ifdef GENLIB

__MAIN__ void preInitInject() {

    void *handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        logd("[!] xdl_open libart.so failed");
        return;
    }
    void *addr = xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr);
    if (addr == nullptr) {
        logd("[!] xdl_sym JNI_GetCreatedJavaVMs failed");
        return;
    }

    // logd("[*] %d JNI_GetCreatedJavaVMs -> %p", getpid(), addr);

    xdl_close(handle);

    using JNI_GetCreatedJavaVMs_t = jint (*)(JavaVM **vmBuf, jsize bufLen, jsize *nVMs);
    auto JNI_GetCreatedJavaVMs = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(addr);
    JavaVM *vm = nullptr;
    jsize nVMs = 0;
    JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);
    // logd("[*] vm -> %p | nVMs -> %d", vm, nVMs);

    if (vm == nullptr) {
        return;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return;
    }

    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        return;
    }

    JNI_OnLoad(vm, nullptr);
}

#endif