//
// Created by lzy on 2023/7/27.
//

#ifndef IL2CPPHOOKER_DOBBYHOOKER_H
#define IL2CPPHOOKER_DOBBYHOOKER_H

#include "HookBase/HookBase.hpp"

class DobbyHooker : public HookBase {

private:
public:
    MACRO_HIDE_SYMBOL
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr)
            return;
        auto target = reinterpret_cast<void *>(mPtr);
        DobbyDestroy(target);
        if (voidInfoCache.count(target) > 0) {
            void *srcCall = voidInfoCache[target];
            if (srcCall != nullptr) {
                voidInfoCache.erase(target);
            }
        }
    }

    MACRO_HIDE_SYMBOL static int registerInstrument(void *address, dobby_instrument_callback_t instrumentFunc) {
        int status = DobbyInstrument(address, instrumentFunc);
        return status;
    }

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
        dobby_disable_near_branch_trampoline();

        int status = -1;
        void *voidPtrFunc = reinterpret_cast<void *>(replaceFunction);
        dobby_dummy_func_t pVoid = reinterpret_cast<dobby_dummy_func_t>(voidPtrFunc);
        dobby_dummy_func_t replaceFunc = (dobby_dummy_func_t)(pVoid);
        dobby_dummy_func_t srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DOBBY:
            if (replaceFunc == nullptr)
                break;
            status = DobbyHook(target, replaceFunc, &srcCall);
            break;
        case HookType::HOOK_RET_NOP_0:
            status = DobbyHook(target, function_ret_0, nullptr);
            break;
        case HookType::HOOK_RET_NOP_1:
            status = DobbyHook(target, function_ret_1, nullptr);
            break;
        default:
            loge("Unknown HookType: %p", type);
            break;
        }
        voidInfoCache.insert({mPtr, srcCall});
        return status;
    }
};

#endif // IL2CPPHOOKER_DOBBYHOOKER_H
