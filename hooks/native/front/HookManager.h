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
#include "HookImpl/ShadowHooker.h"

#include <atomic>
#include <type_traits>

enum class HookerType {
    Frida,
    Dobby,
    Inline
};

constexpr HookerType defaultHookerType = HookerType::Dobby;

class HookManager {
private:
    // 使用 atomic 保证线程安全
    static inline std::atomic<int> CountHookALL{0};
    static inline std::atomic<int> CountHookPTR{0};
    static inline std::atomic<int> CountHookLAMBDA{0};

public:
    // 获取统计信息
    static int getHookCount() { return CountHookALL.load(); }
    static int getPtrHookCount() { return CountHookPTR.load(); }
    static int getLambdaHookCount() { return CountHookLAMBDA.load(); }
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr) {
            logw("UnRegisterHook: nullptr provided");
            return;
        }
        
        switch (defaultHookerType) {
        case HookerType::Frida:
#ifdef USE_FRIDA_GUM
            FridaHooker::UnRegisterHook(mPtr);
#else
            loge("UnRegisterHook: Frida backend not compiled");
#endif
            break;
        case HookerType::Dobby:
            DobbyHooker::UnRegisterHook(mPtr);
            break;
        case HookerType::Inline:
            loge("UnRegisterHook: Inline backend not implemented");
            break;
        default:
            loge("UnRegisterHook: Unknown hooker type");
            break;
        }
    }

    template <typename Callable>
    static int registerHook(void *mPtr, const Callable &func) {
        return registerHook(mPtr, defaultHookerType, func);
    }

    template <typename Callable>
    static int registerHook(void *mPtr, HookerType type, const Callable &func) {
        if (mPtr == nullptr) {
            loge("registerHook: nullptr provided");
            return -1;
        }

        CountHookALL.fetch_add(1, std::memory_order_relaxed);
        
        void *bridge = nullptr;
        if constexpr (std::is_function_v<std::remove_pointer_t<Callable>>) {
            // 函数指针
            bridge = reinterpret_cast<void *>(func);
            CountHookPTR.fetch_add(1, std::memory_order_relaxed);
        } else if constexpr (is_std_function<Callable>::value) {
            // std::function
            bridge = REGISTER_LAMBDA(func);
            CountHookLAMBDA.fetch_add(1, std::memory_order_relaxed);
        } else {
            // Lambda 或其他可调用对象
            bridge = REGISTER_LAMBDA(func);
            CountHookLAMBDA.fetch_add(1, std::memory_order_relaxed);
        }

        if (bridge == nullptr) {
            loge("registerHook: failed to create bridge function");
            return -1;
        }

        switch (type) {
        case HookerType::Frida:
#ifdef USE_FRIDA_GUM
            return FridaHooker::registerHook(mPtr, HookType::HOOK_DEFAULT, bridge);
#else
            loge("registerHook: Frida backend not compiled");
            return -1;
#endif
        case HookerType::Dobby:
            return DobbyHooker::registerHook(mPtr, HookType::HOOK_DEFAULT, bridge);
        case HookerType::Inline:
            loge("registerHook: Inline backend not implemented");
            return -1;
        default:
            loge("registerHook: Unknown hooker type");
            return -1;
        }
    }

    [[maybe_unused]]
    MACRO_HIDE_SYMBOL static int registerInstrument(void *address, dobby_instrument_callback_t instrumentFunc) {
        if (address == nullptr || instrumentFunc == nullptr) {
            loge("registerInstrument: invalid parameters");
            return -1;
        }
        return DobbyHooker::registerInstrument(address, instrumentFunc);
    }

    template <typename... Args>
    MACRO_HIDE_SYMBOL static inline void *srcCall(void *mPtr, Args... args) {
        if (mPtr == nullptr) {
            loge("srcCall: nullptr provided");
            return nullptr;
        }
        
        auto it = HookBase::voidInfoCache.find(mPtr);
        if (it == HookBase::voidInfoCache.end()) {
            loge("srcCall: original function not found for %p", mPtr);
            return nullptr;
        }
        
        if (it->second == nullptr) {
            loge("srcCall: original function is nullptr for %p", mPtr);
            return nullptr;
        }
        
        auto originalFunction = reinterpret_cast<void *(*)(Args...)>(it->second);
        return originalFunction(args...);
    }

    template <typename... Args>
    MACRO_HIDE_SYMBOL static inline void *CallAddress(void *address, Args... args) {
        if (address == nullptr) {
            loge("CallAddress: nullptr provided");
            return nullptr;
        }
        
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