//
// Created by lzy on 2023/7/27.
//

#ifndef IL2CPPHOOKER_HOOKBASE__H
#define IL2CPPHOOKER_HOOKBASE__H

// #include "magic_enum.hpp"
#include <map>

#include "front/HookTemplate.h"
#include "front/InsCheck.h"

#include "HookImpl/HookBase/HookLog.h"

#include "dobby.h"
#include "gumpp.hpp"
#include "shadowhook.h"
#include "template.h"

#define MACRO_HIDE_SYMBOL __attribute__((visibility("hidden")))
#define MACRO_SHOW_SYMBOL __attribute__((visibility("default")))

enum HookType {
    HOOK_DEFAULT,
    HOOK_RET_NOP_0,
    HOOK_RET_NOP_1,
    HOOK_Unity,
    HOOK_SHORT,
    HOOK_SHORT_0,
    HOOK_SHORT_1
};

//#define REGISTER_HOOK(TYPE, FUNC_TYPE) \
//template<typename... Args> \
//MACRO_HIDE_SYMBOL static void registerHook(const MethodInfo *methodInfo, HookType type, const FUNC_TYPE<Args...> & replaceFunction = nullptr) { \
//    HookManager::registerHook(methodInfo, type, reinterpret_cast<FuncType<Args...>>(replaceFunction)); \
//}

class HookBase {

protected:
    inline static dobby_dummy_func_t function_ret_0 = reinterpret_cast<dobby_dummy_func_t>((void *)(*[]() { return nullptr; }));
    inline static dobby_dummy_func_t function_ret_1 = reinterpret_cast<dobby_dummy_func_t>((void *)(*[]() { return (void *)1; }));

public:
    inline static std::map<void *, void *> voidInfoCache = {};
};
#endif // IL2CPPHOOKER_HOOKBASE__H