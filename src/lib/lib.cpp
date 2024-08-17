

#include "main.h"
#include <KittyMemoryEx.hpp>

static JavaVM *g_jvm;
static JNIEnv *env;
static std::thread *g_thread = NULL;

void serializeToPipe(int pipe_fd, const std::vector<std::string> &data) {
}

void deserializeFromPipe(int pipe_fd, std::vector<std::string> &data) {
}

lua_State *G_LUA = NULL;

#include <LuaSocket/LuaReplClient.hpp>
#include <LuaSocket/LuaReplServer.hpp>

extern int installRepl(const std::vector<std::string> &suggestions, std::function<void(const std::string &)> callback);

std::vector<std::string> getLuaCommands(lua_State *L) {
    return {"123", "asdf", "0912j39012j390"};
}

const char *PIPE_NAME = "/data/local/tmp/0912j39012j390";

// run on remote
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

// run on local
void start_local_repl() {
    LuaReplClient client(std::to_string(SOCKET_PORT));
    client.connect();
    std::vector<std::string> customSuggestions = {".help", ".exit", "exampleCommand"};
    installRepl(customSuggestions, [&](const std::string &input) {
        if (input == "exit" || input == "q") {
            client.close_connect();
        } else {
            client.send_message(input);
        }
    });
}

void repl(lua_State *L) {
    logd("[*] start lua repl | Debug Mode");
    std::vector<std::string> customSuggestions = {".help", ".exit", "exampleCommand"};
    installRepl(customSuggestions, [&](const std::string &input) {
        if (input == "exit" || input == "q")
            exit(0);
        if (input.empty())
            return;
        int status = luaL_dostring(L, input.c_str());
        if (reinterpret_cast<LUA_STATUS &>(status) != LUA_STATUS::LUA_OK_) {
            const char *msg = lua_tostring(L, -1);
            lua_writestringerror("%s\n", msg);
            lua_pop(L, 1);
        }
    });
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {

    S_TYPE = vm == nullptr ? START_TYPE::DEBUG : START_TYPE::SOCKET;

    std::string msg = fmt::format("[+] CURRENT -> {} | {} | {}",
                                  (int)getpid(),
                                  KittyMemoryEx::getProcessName(getpid()),
                                  magic_enum::enum_name(S_TYPE));
    logd("%s", msg.c_str());
    std::cout << msg << std::endl;

    g_thread = new std::thread([=]() {
        if (vm != nullptr) {
            logd("------------------- JNI_OnLoad -------------------");
            if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_OK) {
                logd("[*] GetEnv OK | env:%p | vm:%p", env, vm);
            }
            if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                logd("[*] AttachCurrentThread OK");
            }
            g_jvm = vm;
        }
        pthread_setname_np(pthread_self(), EXEC_NAME);
        startLuaVM();
    });

    if (S_TYPE == START_TYPE::DEBUG && g_thread->joinable()) {
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

static int countRestartTimes = 0;

void initVM() {
    if (++countRestartTimes > 3)
        raise(SIGKILL);

    lua_State *L = luaL_newstate();

    G_LUA = std::ref(L);

    luaL_openlibs(L);

    bind_libs(L);

    startRepl(L);

    // test(L);

    // lua_close(L);
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