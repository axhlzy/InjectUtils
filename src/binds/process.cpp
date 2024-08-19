#include "bindings.h"
#include "log.h"

#include <fstream>
#include <include/sys/inotify.h>
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

jobject getAppClassLoader() {

    if (g_jvm->AttachCurrentThread(&g_env, nullptr) != JNI_OK) {
        logd("[!] AttachCurrentThread Failed");
        return nullptr;
    };

    jclass cls_Context = g_env->GetObjectClass(g_application);
    if (cls_Context == NULL) {
        logd("[-] Cannot find Context class");
        console->error("[-] Cannot find Context class");
        return nullptr;
    }
    jmethodID mid_getClassLoader = g_env->GetMethodID(cls_Context, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (mid_getClassLoader == NULL) {
        logd("[-] Cannot find getClassLoader method");
        console->error("[-] Cannot find getClassLoader method");
        return nullptr;
    }
    jobject classLoader = g_env->CallObjectMethod(g_application, mid_getClassLoader);
    if (classLoader == NULL) {
        logd("[-] Failed to get ClassLoader");
        console->error("[-] Failed to get ClassLoader");
        return nullptr;
    }

    return classLoader;
}

jclass findClass(const char *className) {

    if (g_jvm->AttachCurrentThread(&g_env, nullptr) != JNI_OK) {
        logd("[!] AttachCurrentThread Failed");
        return nullptr;
    };

    jclass cls_ClassLoader = g_env->FindClass("java/lang/ClassLoader");
    if (cls_ClassLoader == NULL) {
        logd("[-] Cannot find ClassLoader class");
        console->error("[-] Cannot find ClassLoader class");
        return NULL;
    }
    jmethodID mid_loadClass = g_env->GetMethodID(cls_ClassLoader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (mid_loadClass == NULL) {
        logd("[-] Cannot find loadClass method");
        console->error("[-] Cannot find loadClass method");
        return NULL;
    }
    return (jclass)g_env->CallObjectMethod(getAppClassLoader(), mid_loadClass, g_env->NewStringUTF(className));
}

jmethodID findMethd(const char *className, const char *methodName, const char *methodSignature) {
    if (g_jvm->AttachCurrentThread(&g_env, nullptr) != JNI_OK) {
        logd("[!] AttachCurrentThread Failed");
        return nullptr;
    };
    jmethodID methodId = g_env->GetMethodID(findClass(className), methodName, methodSignature);
    if (methodId == NULL) {
        logd("[-] Cannot find %s method", methodName);
        console->error("[-] Cannot find '{}' method", methodName);
        return NULL;
    }
    return methodId;
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

    luabridge::getGlobalNamespace(L)
        .addFunction("getApp", []() { return (PTR)g_application; })
        .addFunction("showApp", []() { console->info("g_application : {:p}", (void *)g_application); })
        .addFunction("showAppClassLoader", []() { console->info("g_application : {:p}", (void *)getAppClassLoader()); })
        .addFunction("findClass", findClass)
        .addFunction("findMethd", findMethd)
        .addFunction("testFindMethod", []() { console->info("{:p}", (void *)findMethd("com.unity3d.player.UnityPlayerActivity", "onCreate", "(Landroid/os/Bundle;)V")); });

    luabridge::getGlobalNamespace(L)
        .addVariable("G_LUA", (PTR)G_LUA)
        .addVariable("g_jvm", (PTR)g_jvm)
        .addVariable("g_thread", (PTR)g_thread)
        .addVariable("S_TYPE", (PTR)S_TYPE)
        .addVariable("S_TYPE_NAME", magic_enum::enum_name(S_TYPE))
        .addVariable("g_application", (PTR)g_application)
        .addVariable("g_env", (PTR)g_env);
}