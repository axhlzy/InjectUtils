#include "KittyMemoryEx.hpp"
#include "config.h"
#include "jni_helper.h"
#include "jvmti_helper.h"
#include "main.h"
#include "repl_manager.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    S_TYPE = (vm == nullptr) ? DEBUG : SOCKET;

    const std::string msg = fmt::format(
        "[+] CURRENT -> PID: {} | {} | {}", 
        getpid(),
        KittyMemoryEx::getProcessName(getpid()), 
        magic_enum::enum_name(S_TYPE));
    
    logd("%s", msg.c_str());
    std::cout << msg << std::endl;

    g_thread = std::make_unique<std::thread>([vm]() {
        if (vm != nullptr) {
            g_jvm = vm;
            
            logd("------------------- JNI_OnLoad -------------------");
            
            if (vm->AttachCurrentThread(&g_env, nullptr) == JNI_OK) {
                logd("[*] AttachCurrentThread OK");
            }
            
            if (vm->GetEnv(reinterpret_cast<void **>(&g_env), JNI_VERSION_1_6) == JNI_OK) {
                logd("[*] GetEnv OK | env:%p | vm:%p", g_env, vm);
            }
            
            // 获取 Application 对象并初始化 ClassLoader
            g_application = getApplication(g_env);
            if (g_application != nullptr) {
                initAppClassLoader(g_env, g_application);
                
                // 启用调试功能（允许 JDWP）
                SetDebuggableRelease(true);
                
                // 动态附加 JVMTI Agent（使用当前 so 文件路径）
                // ref: https://cs.android.com/android/platform/superproject/main/+/main:libcore/dalvik/src/main/java/dalvik/system/VMDebug.java;l=739
                std::string agentPath = GetCurrentSoPath();
                if (!agentPath.empty()) {
                    if (AttachJvmtiAgent(g_env, agentPath.c_str(), g_classLoader)) {
                        logd("[*] JVMTI agent attachment completed");
                    } else {
                        loge("[!] JVMTI agent attachment failed");
                    }
                } else {
                    loge("[!] Failed to get current SO path, cannot attach agent");
                }

            } else {
                loge("[!] Failed to get Application object");
            }
        }
        
        pthread_setname_np(pthread_self(), EXEC_NAME);
        startLuaVM();
        
        if (vm != nullptr) {
            vm->DetachCurrentThread();
        }
    });

    if (S_TYPE == START_TYPE::DEBUG && g_thread->joinable()) {
        g_thread->join();
    }

    return JNI_VERSION_1_6;
}

// noreturn
static int countRestartTimes = 0;

void initVM() {
    if (++countRestartTimes > Config::MAX_RESTART_TIMES) {
        raise(SIGKILL);
    }

    lua_State *L = luaL_newstate();
    G_LUA = std::ref(L);

    luaL_openlibs(L);
    bind_libs(L);

    startRepl(L);

    lua_close(L);
}

void startLuaVM() {
    reg_crash_handler();
    initVM();
}

#ifdef GENLIB

__MAIN__ void preInitInject() {
    void *handle = xdl_open(Config::LIBART_SO, XDL_DEFAULT);
    if (handle == nullptr) {
        logd("[!] xdl_open %s failed", Config::LIBART_SO);
        return;
    }
    void *addr = xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr);
    if (addr == nullptr) {
        logd("[!] xdl_sym JNI_GetCreatedJavaVMs failed");
        return;
    }

    // logd("[*] %d JNI_GetCreatedJavaVMs -> %p", getpid(), addr);

    xdl_close(handle);

    using JNI_GetCreatedJavaVMs_t =
        jint (*)(JavaVM **vmBuf, jsize bufLen, jsize *nVMs);
    auto JNI_GetCreatedJavaVMs = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(addr);
    JavaVM *vm = nullptr;
    jsize nVMs = 0;
    JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);
    // logd("[*] vm -> %p | nVMs -> %d", vm, nVMs);

    if (vm == nullptr) {
        logd("[!] JNI_GetCreatedJavaVMs failed");
        return;
    }

    JNI_OnLoad(vm, nullptr);
}

#endif