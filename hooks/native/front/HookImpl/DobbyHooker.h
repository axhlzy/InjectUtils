//
// Created by lzy on 2023/7/27.
//

#ifndef IL2CPPHOOKER_DOBBYHOOKER_H
#define IL2CPPHOOKER_DOBBYHOOKER_H

#include "HookBase/HookBase.hpp"

/**
 * @brief Dobby Hook 实现
 * 
 * 基于 Dobby 框架的 Hook 实现
 */
class DobbyHooker : public HookBase {
public:
    /**
     * @brief 注销 Hook
     */
    MACRO_HIDE_SYMBOL
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr) {
            logw("DobbyHooker::UnRegisterHook: nullptr provided");
            return;
        }
        
        auto target = reinterpret_cast<void *>(mPtr);
        
        // 销毁 Hook
        int status = DobbyDestroy(target);
        if (status != 0) {
            loge("DobbyHooker::UnRegisterHook: DobbyDestroy failed with status %d", status);
        }
        
        // 移除缓存
        removeCache(target);
    }

    /**
     * @brief 注册指令插桩
     */
    MACRO_HIDE_SYMBOL 
    static int registerInstrument(void *address, dobby_instrument_callback_t instrumentFunc) {
        if (address == nullptr || instrumentFunc == nullptr) {
            loge("DobbyHooker::registerInstrument: invalid parameters");
            return -1;
        }
        
        int status = DobbyInstrument(address, instrumentFunc);
        if (status != 0) {
            loge("DobbyHooker::registerInstrument: failed with status %d", status);
        }
        return status;
    }

    /**
     * @brief 注册 Hook（模板版本）
     */
    template <typename... Args>
    MACRO_HIDE_SYMBOL 
    static int registerHook(void *mPtr, HookType type, FuncType<Args...> replaceFunction = nullptr) {
        if (mPtr == nullptr) {
            loge("DobbyHooker::registerHook: nullptr provided");
            return -1;
        }
        return registerHook(mPtr, type, reinterpret_cast<void *>(replaceFunction));
    }

    /**
     * @brief 注册 Hook（通用版本）
     */
    MACRO_HIDE_SYMBOL 
    static int registerHook(void *mPtr, HookType type, void *replaceFunction = nullptr) {
        if (mPtr == nullptr) {
            loge("DobbyHooker::registerHook: nullptr provided");
            return -1;
        }
        
        auto target = reinterpret_cast<void *>(mPtr);
        dobby_disable_near_branch_trampoline();

        int status = -1;
        dobby_dummy_func_t srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (replaceFunction == nullptr) {
                loge("DobbyHooker::registerHook: replaceFunction is nullptr for HOOK_DEFAULT");
                break;
            }
            status = DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(replaceFunction), &srcCall);
            break;
            
        case HookType::HOOK_RET_NOP_0:
            status = DobbyHook(target, function_ret_0, nullptr);
            break;
            
        case HookType::HOOK_RET_NOP_1:
            status = DobbyHook(target, function_ret_1, nullptr);
            break;
            
        default:
            loge("DobbyHooker::registerHook: Unknown HookType %d", static_cast<int>(type));
            break;
        }
        
        if (status != 0) {
            loge("DobbyHooker::registerHook: DobbyHook failed with status %d", status);
        } else {
            // 成功时插入缓存
            insertCache(mPtr, srcCall);
        }
        
        return status;
    }
};

#endif // IL2CPPHOOKER_DOBBYHOOKER_H
