//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_INLINEHOOKER_H
#define IL2CPPHOOKER_INLINEHOOKER_H

#include "HookBase/HookBase.hpp"

#if defined(__aarch64__)
#include "And64InlineHook.hpp"
#define ADD_HOOK(symbol, replace, result) \
    A64HookFunction(symbol, replace, (void **)result)
#define UNHOOK(symbol) \
    // not impl unhook ...
#elif defined(__arm__)
#include "inlineHook.h"
#define ADD_HOOK(symbol, replace, result) \
    registerInlineHook((uint32_t)(uintptr_t)symbol, (uint32_t)(uintptr_t)replace, (uint32_t **)(uintptr_t)result)
#define UNHOOK(symbol) \
    inlineUnHook((uint32_t)(uintptr_t)symbol)
#endif

class InlineHooker : public HookBase {

private:
public:
    MACRO_HIDE_SYMBOL
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr)
            return;
        auto target = reinterpret_cast<void *>(mPtr);
        UNHOOK(mPtr);
        if (voidInfoCache.count(target) > 0) {
            void *srcCall = voidInfoCache[target];
            if (srcCall != nullptr) {
                voidInfoCache.erase(target);
            }
        }
    }

    template <typename... Args>
    MACRO_HIDE_SYMBOL static int registerHook(void *mPtr, HookType type, FuncType<Args...> replaceFunction = nullptr) {
        if (mPtr == nullptr)
            return -1;
        return registerHook(mPtr, type, reinterpret_cast<void *>(replaceFunction));
    }

    MACRO_HIDE_SYMBOL static int registerHook(void *mPtr, HookType type, void *replaceFunction = nullptr) {
#ifdef DEBUG_PROJECT
        if (replaceFunction == nullptr) {
            void *base = Global<Data>::Get()->getIl2cppInfo().dli_fbase;
            void *target = (void *)((unsigned long)mPtr - (unsigned long)base);
            const MethodInfo *method = IL2CPP::getMethodInfoFromAddress(mPtr);
            LOGE("registerHook replaceFunction is NULL [ case '{} @ {}' ]\n\t{}, {}, {}",
                 method != nullptr ? method->name : "unknown", target,
                 mPtr, magic_enum::enum_name(type), replaceFunction);
        }
#endif
        if (mPtr == nullptr)
            return -1;
        auto target = reinterpret_cast<void *>(mPtr);

        int status = 1;
        void *voidPtrFunc = reinterpret_cast<void *>(replaceFunction);
        dobby_dummy_func_t pVoid = reinterpret_cast<dobby_dummy_func_t>(voidPtrFunc);
        dobby_dummy_func_t replaceFunc = (dobby_dummy_func_t)(pVoid);
        dobby_dummy_func_t srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (replaceFunc == nullptr)
                break;
            ADD_HOOK(target, replaceFunc, &srcCall);
            break;
        case HookType::HOOK_RET_NOP_0:
            ADD_HOOK(target, function_ret_0, nullptr);
            break;
        case HookType::HOOK_RET_NOP_1:
            ADD_HOOK(target, function_ret_1, nullptr);
            break;
        default:
            loge("Unknown HookType: %p", type);
            break;
        }
        voidInfoCache.insert(std::pair<void *, dobby_dummy_func_t>((void *)mPtr, srcCall));
        return status;
    }
};

#endif // IL2CPPHOOKER_INLINEHOOKER_H