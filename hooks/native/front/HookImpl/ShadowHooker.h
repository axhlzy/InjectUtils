//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_SHADOWHOOKER_H
#define IL2CPPHOOKER_SHADOWHOOKER_H

#include "HookBase/HookBase.hpp"

/**
 * @brief ShadowHook 实现
 * 
 * 基于 ShadowHook 框架的 Hook 实现
 */
class ShadowHooker : public HookBase {
public:
    /**
     * @brief 注册 Hook（模板版本）
     */
    template <typename... Args>
    MACRO_HIDE_SYMBOL 
    static int registerHook(void *mPtr, HookType type, FuncType<Args...> replaceFunction = nullptr) {
        if (mPtr == nullptr) {
            loge("ShadowHooker::registerHook: nullptr provided");
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
            loge("ShadowHooker::registerHook: nullptr provided");
            return -1;
        }
        
        auto target = reinterpret_cast<void *>(mPtr);
        void *srcCall = nullptr;

        switch (type) {
        case HookType::HOOK_DEFAULT:
            if (replaceFunction == nullptr) {
                loge("ShadowHooker::registerHook: replaceFunction is nullptr for HOOK_DEFAULT");
                return -1;
            }
            if (shadowhook_hook_func_addr(target, replaceFunction, &srcCall) != 0) {
                loge("ShadowHooker::registerHook: shadowhook_hook_func_addr failed");
                return -1;
            }
            break;
            
        case HookType::HOOK_RET_NOP_0:
            if (shadowhook_hook_func_addr(target, function_ret_0, nullptr) != 0) {
                loge("ShadowHooker::registerHook: shadowhook_hook_func_addr failed for HOOK_RET_NOP_0");
                return -1;
            }
            break;
            
        case HookType::HOOK_RET_NOP_1:
            if (shadowhook_hook_func_addr(target, function_ret_1, nullptr) != 0) {
                loge("ShadowHooker::registerHook: shadowhook_hook_func_addr failed for HOOK_RET_NOP_1");
                return -1;
            }
            break;
            
        default:
            loge("ShadowHooker::registerHook: Unknown HookType %d", static_cast<int>(type));
            return -1;
        }
        
        // 插入缓存
        insertCache(mPtr, srcCall);
        return 0;
    }
};

#endif // IL2CPPHOOKER_SHADOWHOOKER_H
