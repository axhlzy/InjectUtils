#if !defined(MAIN_CPP_H)
#define MAIN_CPP_H

#include "HookManager.h"
#include "LuaLibrary.h"
#include "UnityResolve.hpp"
#include "bindings.h"
#include "capstone/capstone.h"
#include "common_enum.hpp"
#include "debugbreak.h"
#include "dobby.h"
#include "keystone/keystone.h"
#include "log.h"
#include "magic_enum_all.hpp"
#include "syscalls_enum.h"
#include "xdl.h"
#include <algorithm>
#include <android/log.h>
#include <iostream>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <dlfcn.h>
#define GetModuleHandle dlopen
#endif
#ifdef DEBUG_PROJECT
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

// 兼容luabridge3对void*特化成 userdata 导致控制台不能直接输入数字视作void*的问题
#ifndef PTR
#define PTR uintptr_t
#endif

#ifndef EXEC_NAME
#define EXEC_NAME "Injector"
#endif

#define __MAIN__ __attribute__((constructor))
#define __EXIT__ __attribute__((destructor))
#define NORETURN __attribute__((noreturn))
#define NOINLINE __attribute__((__noinline__))
#define INLINE __attribute__((__inline__))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define xASM(x) __asm __volatile__(x)
#define MACRO_HIDE_SYMBOL __attribute__((visibility("hidden")))
#define MACRO_SHOW_SYMBOL __attribute__((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved);

__attribute__((visibility("default"))) void startLuaVM();
__attribute__((visibility("default"))) void initVM();

#ifdef __cplusplus
}
#endif

// #define LUA_OK           0
// #define LUA_YIELD        1
// #define LUA_ERRRUN       2
// #define LUA_ERRSYNTAX    3
// #define LUA_ERRMEM       4
// #define LUA_ERRERR       5
enum LUA_STATUS {
    LUA_OK_ = 0,
    LUA_YIELD_ = 1,
    LUA_ERRRUN_ = 2,
    LUA_ERRSYNTAX_ = 3,
    LUA_ERRMEM_ = 4,
    LUA_ERRERR_ = 5
};

enum START_TYPE {
    DEBUG,
    SOCKET
};

static START_TYPE S_TYPE = DEBUG;
static int SOCKET_PORT = 8024;

extern lua_State *G_LUA;

void reg_crash_handler();

INLINE void init_kittyMemMgr();

std::string getSelfPath();
std::string getThreadName(pid_t id);
std::string getStat(pid_t tid);

void set_selinux_state(bool status = false);

void inject(pid_t pid);

#endif // MAIN_CPP_H