//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_SHADOWHOOKER_H
#define IL2CPPHOOKER_SHADOWHOOKER_H

#include "HookBase/HookBase.hpp"

class ShadowHooker : public HookBase {

private:
public:
    template <typename... Args>
    MACRO_HIDE_SYMBOL static int registerHook(void *mPtr, HookType type, FuncType<Args...> replaceFunction = nullptr) {
        if (mPtr == nullptr)
            return -1;
        return registerHook(mPtr, type, reinterpret_cast<void *>(replaceFunction));
    }

    MACRO_HIDE_SYMBOL static int registerHook(void *mPtr, HookType type, void *replaceFunction = nullptr) {

        if (mPtr == nullptr)
            return -1;
        auto target = reinterpret_cast<void *>(mPtr);
        int status = 1;
        void *pVoid = reinterpret_cast<void *>(replaceFunction);
        void *replaceFunc = (void *)(pVoid);
        void *srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (replaceFunc == nullptr)
                break;
            shadowhook_hook_func_addr(target, replaceFunc, &srcCall);
            break;
        case HookType::HOOK_RET_NOP_0:
            shadowhook_hook_func_addr(target, function_ret_0, nullptr);
            break;
        case HookType::HOOK_RET_NOP_1:
            shadowhook_hook_func_addr(target, function_ret_1, nullptr);
            break;
        default:
            loge("Unknown HookType: %p", type);
            break;
        }
        voidInfoCache.insert(std::pair<void *, dobby_dummy_func_t>((void *)mPtr, srcCall));
        return status;
    };
};

#endif // IL2CPPHOOKER_SHADOWHOOKER_H
