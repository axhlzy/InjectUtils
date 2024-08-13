//
// Created by A on 2022/3/25.
//

#ifndef InjectDemo_HOOK_MANAGER_H
#define InjectDemo_HOOK_MANAGER_H

#include "HookImpl/HookBase/HookBase.hpp"

#include "HookTemplate.h"
#include "LambdaTram/LambdaTram.hpp"

#include "HookImpl/DobbyHooker.h"
#include "HookImpl/FridaHooker.h"
// #include "HookImpl/InlineHooker.h"
#include "HookImpl/ShadowHooker.h"

enum class HookerType {
    Frida,
    Dobby,
    Inline
};

constexpr HookerType defaultHookerType = HookerType::Dobby;

class HookManager {

private:
    // _ZN11HookManager12CountHookALLE -> HookManager::CountHookALL
    static inline int CountHookALL = 0;
    // _ZN11HookManager12CountHookPTRE -> HookManager::CountHookPTR
    static inline int CountHookPTR = 0;
    // _ZN11HookManager14CountHookLAMBDA -> HookManager::CountHookLAMBDA
    static inline int CountHookLAMBDA = 0;
    // not used
    // static inline auto HookUsingBackend = magic_enum::enum_name(defaultHookerType);

public:
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr)
            return;
        switch (defaultHookerType) {
        case HookerType::Frida:
#ifdef USE_FRIDA_GUM
            FridaHooker::UnRegisterHook(mPtr);
#else
            loge("UnRegisterHook Frida NOT IMPLEMENTED");
#endif
            break;
        case HookerType::Dobby:
            DobbyHooker::UnRegisterHook(mPtr);
            break;
            // case HookerType::Inline:
            //     InlineHooker::UnRegisterHook(mPtr);
            //     break;
        }
    }

    template <typename Callable>
    static int registerHook(void *mPtr, const Callable &func) {
        return registerHook(mPtr, defaultHookerType, func);
    }

    template <typename Callable>
    static int registerHook(void *mPtr, HookerType type, const Callable &func) {

        ++CountHookALL;
        void *bridge;
        if constexpr (std::is_function_v<std::remove_pointer_t<Callable>>) {
            // Callable 是函数指针
            bridge = (void *)func;
            ++CountHookPTR;
        } else if constexpr (is_std_function<Callable>::value) {
            // Callable 是 std::function
            bridge = REGISTER_LAMBDA(func);
            ++CountHookLAMBDA;
        } else {
            // 其他类型
            bridge = REGISTER_LAMBDA(func);
            ++CountHookLAMBDA;
        }
        switch (defaultHookerType) {
        case HookerType::Frida:
#ifdef USE_FRIDA_GUM
            return FridaHooker::registerHook(mPtr, HookType::HOOK_DEFAULT, bridge);
#else
            loge("registerHook Frida NOT IMPLEMENTED");
#endif
        case HookerType::Dobby:
            return DobbyHooker::registerHook(mPtr, HookType::HOOK_DEFAULT, bridge);
            // case HookerType::Inline:
            //     return InlineHooker::registerHook(mPtr, type, bridge);
        }
    }

    [[maybe_unused]]
    MACRO_HIDE_SYMBOL static int registerInstrument(void *address, dobby_instrument_callback_t instrumentFunc) {
        return DobbyHooker::registerInstrument(address, instrumentFunc);
    }

    template <typename... Args>
    MACRO_HIDE_SYMBOL static inline void *srcCall(void *mPtr, Args... args) {
        if (mPtr == nullptr)
            return nullptr;
        logw("srcCall: %p", mPtr);
        auto it = HookBase::voidInfoCache.find(mPtr);
        if (it == HookBase::voidInfoCache.end()) {
            loge("srcCall: %p, failed", mPtr);
            return nullptr;
        }
        // std::function<void*(Args...)> srcFunction = reinterpret_cast<void*(*)(Args...)>(it->second);
        auto originalFunction = reinterpret_cast<void *(*)(Args...)>(it->second);
        return originalFunction(args...);
    }

    template <typename... Args>
    MACRO_HIDE_SYMBOL static inline void *CallAddress(void *address, Args... args) {
        using FuncType = void *(*)(Args...);
        auto func = reinterpret_cast<FuncType>(address);
        return func(args...);
    }
};

#define SrcCall(mPtr, ...) HookManager::srcCall(mPtr, __VA_ARGS__)
#define CallAddress(address, ...) HookManager::CallAddress(address, __VA_ARGS__)
#define HK(address, func) HookManager::registerHook(address, func)
#define UHK(mPtr) HookManager::UnRegisterHook(mPtr)

#endif