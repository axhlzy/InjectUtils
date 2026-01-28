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

    // luabridge::getGlobalNamespace(L)
    //     .addVariable("G_LUA", (PTR)G_LUA)
    //     .addVariable("g_jvm", (PTR)g_jvm)
    //     .addVariable("g_thread", (PTR)g_thread)
    //     .addVariable("S_TYPE", (PTR)S_TYPE)
    //     .addVariable("S_TYPE_NAME", magic_enum::enum_name(S_TYPE))
    //     .addVariable("g_application", (PTR)g_application)
    //     .addVariable("g_env", (PTR)g_env);
}

// impl hook for thread

// bionic/libc/bionic/pthread_internal.h
#include "HookManager.h"
#include "KittyMemoryEx.hpp"
#include "bionic/pthread_internal.h"
#include "fmt/core.h"
#include "rttr/registration"
#include "xdl.h"

using namespace rttr;

RTTR_REGISTRATION {
    registration::class_<pthread_internal_t>("pthread_internal_t")
        .property("next", &pthread_internal_t::next)
        .property("prev", &pthread_internal_t::prev)
        .property("tid", &pthread_internal_t::tid)
        .property("attr", &pthread_internal_t::attr)
        // .property("join_state", &pthread_internal_t::join_state)
        .property("cleanup_stack", &pthread_internal_t::cleanup_stack)
        .property("start_routine", &pthread_internal_t::start_routine)
        .property("return_value", &pthread_internal_t::return_value)
        .property("start_mask", &pthread_internal_t::start_mask)
        .property("alternate_signal_stack", &pthread_internal_t::alternate_signal_stack)
        .property("shadow_call_stack_guard_region", &pthread_internal_t::shadow_call_stack_guard_region)
        .property("stack_top", &pthread_internal_t::stack_top)
        // .property("terminating", &pthread_internal_t::terminating)
        // .property("startup_handshake_lock", &pthread_internal_t::startup_handshake_lock)
        .property("mmap_base", &pthread_internal_t::mmap_base)
        .property("mmap_size", &pthread_internal_t::mmap_size)
        .property("vma_name_buffer", &pthread_internal_t::vma_name_buffer)
        // .property("thread_local_dtors", &pthread_internal_t::thread_local_dtors)
        .property("current_dlerror", &pthread_internal_t::current_dlerror)
        .property("dlerror_buffer", &pthread_internal_t::dlerror_buffer)
        .property("bionic_tls", &pthread_internal_t::bionic_tls)
        .property("errno_value", &pthread_internal_t::errno_value);
}

void check(const std::string &ext, const std::string &contain, void *ptr) {
    if (ext.find(contain) != std::string::npos) {
        void *pc = nullptr;
        void *fp = nullptr;
        void *lr = nullptr;
        void *sp = nullptr;

#if defined(__arm__)
        asm volatile(
            "mov %[result], pc\n"
            : [result] "=r"(pc));
        asm volatile(
            "mov %[result], r7\n"
            : [result] "=r"(fp));
        asm volatile(
            "mov %[result], lr\n"
            : [result] "=r"(lr));
        asm volatile(
            "mov %[result], sp\n"
            : [result] "=r"(sp));

#elif defined(__aarch64__)
        // asm volatile(
        //     "mov %[result], pc\n"
        //     : [result] "=r"(pc));
        asm volatile(
            "mov %[result], x29\n"
            : [result] "=r"(fp));
        asm volatile(
            "mov %[result], lr\n"
            : [result] "=r"(lr));
        asm volatile(
            "mov %[result], sp\n"
            : [result] "=r"(sp));
#else
#error Unsupported architecture
#endif
        fmt::print("\tSTOP -> pc={:p}, fp={:p}, lr={:p}, sp={:p}\n", pc, fp, lr, sp);

        // // 没有做权限检查 dis的时候可能超出区域 触发 sigsegv
        // luaL_dostring(G_LUA, fmt::format("dis {:p}", ptr).c_str());

#if defined(__arm__) || defined(__aarch64__)
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("b #0");
        asm volatile("nop");
        asm volatile("nop");
        asm volatile("nop");
#endif
    }
}

// __start_thread -> static int __pthread_start(void* arg)
void hook_start_thread() {

    // 081: 0000000000083a70    72 FUNC    LOCAL  HIDDEN     14 __start_thread
    // extern "C" __LIBC_HIDDEN__ void __start_thread(int (*fn)(void*), void* arg)
    // let __start_thread_addr = Process.findModuleByName("libc.so").enumerateSymbols().filter(item = > item.name == "__start_thread")[0].address
    void *libcHandle = xdl_open("libc.so", XDL_DEFAULT);
    void *addr = xdl_dsym(libcHandle, "__start_thread", NULL);
    xdl_close(libcHandle);
    if (addr == NULL) {
        console->error("__start_thread not found");
        return;
    }

    using FN = int (*)(void *);
    pid_t pid = getpid();

    // #define USE_XDL false
    HK(addr, [=](FN fn, pthread_internal_t *arg) {
        auto type = rttr::type::get<pthread_internal_t>();
        auto tid = type.get_property("tid").get_value(arg).get_value<pid_t>();
        auto start_routine = type.get_property("start_routine").get_value(arg).get_value<void *>();
        auto maps = KittyMemoryEx::getAddressMap(pid, (uintptr_t)start_routine);
        std::string ext = maps.toString();

        // #if USE_XDL
        //         xdl_info_t info = {0};
        //         void *cache = NULL;
        //         if (xdl_addr(start_routine, &info, &cache)) {
        //             ext = fmt::format("{} @ {} [ {} <- {} ]", info.dli_sname, info.dli_saddr, info.dli_fname, info.dli_fbase);
        //         }
        // #else
        //         Dl_info info;
        //         if (dladdr(start_routine, &info)){
        //             ext = fmt::format("{} @ {} [ {} <- {} ]", info.dli_sname, info.dli_saddr, info.dli_fname, info.dli_fbase);
        //         }
        // #endif

        uintptr_t offset = (uintptr_t)start_routine - maps.startAddress;
        console->info("fn={:p}, arg={:p}\n\ttid:{}, start_routine:{} | {}\n\tstart_routine_arg:{} stack_top:{}\n\t{}",
                      (void *)fn, (void *)arg,
                      tid, start_routine, (void *)offset,
                      arg->start_routine_arg, (void *)arg->stack_top,
                      ext);

        // check(ext, "libbaiduprotect.so", start_routine);

        SrcCall(addr, fn, arg);
    });
}

BINDFUNC(thread) {

    luabridge::getGlobalNamespace(L)
        .addFunction("hook_create_thread", hook_start_thread);
}