//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_FRIDAHOOKER_H
#define IL2CPPHOOKER_FRIDAHOOKER_H

#include "HookBase/HookBase.hpp"

/**
 * @brief Frida Hook 实现
 * 
 * 基于 Frida-Gum 框架的 Hook 实现
 */
class FridaHooker : public HookBase {
public:
    /**
     * @brief 注销 Hook
     */
    MACRO_HIDE_SYMBOL
    static void UnRegisterHook(void *mPtr) {
        if (mPtr == nullptr) {
            logw("FridaHooker::UnRegisterHook: nullptr provided");
            return;
        }
        
        auto target = reinterpret_cast<void *>(mPtr);
        
        // 恢复原始函数
        Gum::Interceptor_obtain()->revert(target);
        
        // 移除缓存
        removeCache(target);
    }

    /**
     * @brief 注册 Hook
     */
    MACRO_HIDE_SYMBOL
    static int registerHook(void *mPtr, HookType type, void *replaceFunction) {
        if (mPtr == nullptr) {
            loge("FridaHooker::registerHook: nullptr provided");
            return -1;
        }
        
        auto target = reinterpret_cast<void *>(mPtr);
        void *srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (replaceFunction == nullptr) {
                loge("FridaHooker::registerHook: replaceFunction is nullptr for HOOK_DEFAULT");
                return -1;
            }
            Gum::Interceptor_obtain()->replace(target, replaceFunction, nullptr, &srcCall);
            break;
            
        case HookType::HOOK_RET_NOP_0:
            Gum::Interceptor_obtain()->replace(target, function_ret_0, nullptr, nullptr);
            break;
            
        case HookType::HOOK_RET_NOP_1:
            Gum::Interceptor_obtain()->replace(target, function_ret_1, nullptr, nullptr);
            break;
            
        default:
            loge("FridaHooker::registerHook: Unknown HookType %d", static_cast<int>(type));
            return -1;
        }
        
        // 插入缓存
        insertCache(mPtr, srcCall);
        return 0;
    }
};

#endif // IL2CPPHOOKER_FRIDAHOOKER_H
