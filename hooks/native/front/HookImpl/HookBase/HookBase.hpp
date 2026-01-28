//
// Created by lzy on 2023/7/27.
//

#ifndef IL2CPPHOOKER_HOOKBASE__H
#define IL2CPPHOOKER_HOOKBASE__H

#include <map>
#include <mutex>

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

/**
 * @brief Hook 基类
 * 
 * 提供所有 Hook 实现的公共功能和数据结构
 */
class HookBase {
protected:
    // 返回 nullptr 的函数
    inline static dobby_dummy_func_t function_ret_0 = 
        reinterpret_cast<dobby_dummy_func_t>((void *)(*[]() -> void* { return nullptr; }));
    
    // 返回 (void*)1 的函数
    inline static dobby_dummy_func_t function_ret_1 = 
        reinterpret_cast<dobby_dummy_func_t>((void *)(*[]() -> void* { return reinterpret_cast<void*>(1); }));

public:
    // 原始函数地址缓存 (目标地址 -> 原始函数地址)
    inline static std::map<void *, void *> voidInfoCache = {};
    
    // 缓存访问互斥锁
    inline static std::mutex cacheMutex;
    
    /**
     * @brief 线程安全地插入缓存
     */
    static void insertCache(void *target, void *original) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        voidInfoCache[target] = original;
    }
    
    /**
     * @brief 线程安全地移除缓存
     */
    static void removeCache(void *target) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        voidInfoCache.erase(target);
    }
    
    /**
     * @brief 线程安全地查找缓存
     */
    static void* findCache(void *target) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = voidInfoCache.find(target);
        return (it != voidInfoCache.end()) ? it->second : nullptr;
    }
};

#endif // IL2CPPHOOKER_HOOKBASE__H