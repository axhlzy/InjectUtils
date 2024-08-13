//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_FRIDAHOOKER_H
#define IL2CPPHOOKER_FRIDAHOOKER_H

#include "HookBase/HookBase.hpp"

class FridaHooker : public HookBase {

private:
public:
    MACRO_HIDE_SYMBOL
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr)
            return;
        auto target = reinterpret_cast<void *>(mPtr);
        Gum::Interceptor_obtain()->revert(target);
        if (voidInfoCache.count(target) > 0) {
            void *srcCall = voidInfoCache[target];
            if (srcCall != nullptr) {
                voidInfoCache.erase(target);
            }
        }
    }

    MACRO_HIDE_SYMBOL
    static int registerHook(void *mPtr, HookType type, void *replaceFunction) {
        if (mPtr == nullptr)
            return -1;
        auto target = reinterpret_cast<void *>(mPtr);

        int status = 1;
        void *voidPtrFunc = reinterpret_cast<void *>(replaceFunction);
        void *srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (voidPtrFunc == nullptr)
                break;
            Gum::Interceptor_obtain()->replace(target, voidPtrFunc, nullptr, &srcCall);
            break;
        case HookType::HOOK_RET_NOP_0:
            Gum::Interceptor_obtain()->replace(target, function_ret_0, nullptr, nullptr);
            break;
        case HookType::HOOK_RET_NOP_1:
            Gum::Interceptor_obtain()->replace(target, function_ret_1, nullptr, nullptr);
            break;
        default:
            loge("Unknown HookType: %p", type);
            break;
        }
        voidInfoCache.insert({mPtr, srcCall});
        return status;
    }
};

#endif // IL2CPPHOOKER_FRIDAHOOKER_H
