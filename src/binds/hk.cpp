/**
 * @file hk.cpp
 * @brief HookManager 的 Lua 绑定实现，支持状态保存和高级 Hook 功能
 * 
 * 功能特性：
 * - 支持函数 Hook（替换、前置、后置）
 * - 保存和恢复 Hook 状态
 * - 支持 Lua 回调函数
 * - 线程安全的 Hook 管理
 * - 参数捕获和修改
 * 
 * Lua 回调代码中可用 ctx 表：
 *   ctx.addr  - 被 Hook 的地址
 *   ctx.args  - 参数表 {[0]=arg0, [1]=arg1, ...}
 *   ctx.ret   - 返回值（仅 leave 中有效）
 *   ctx.skip  - 设为 true 跳过原函数
 */

#include "dobby.h"
#include "HookManager.h"
#include "LambdaTram/LambdaTram.hpp"
#include "bindings.h"

#include <map>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <functional>

using namespace std;

struct HkInfo {
    PTR address;
    PTR original;           // 原函数地址，由 Lua 侧管理
    string enterCode;
    string leaveCode;
    bool isActive;
    string name;
    int hookId;
    
    HkInfo() : address(0), original(0), isActive(false), hookId(-1) {}
};

struct HkContext {
    PTR address;
    uintptr_t args[8];
    uintptr_t returnValue;
    bool skipOriginal;
};

class HkBind {
private:
    inline static map<PTR, shared_ptr<HkInfo>> hookInfoMap;
    inline static map<int, PTR> hookIdMap;
    inline static int nextHookId = 1;
    inline static mutex hookMutex;
    inline static recursive_mutex luaMutex;  // 递归锁 - 允许同一线程重入
    inline static vector<shared_ptr<HkInfo>> savedHooks;

    static int generateHookId() {
        lock_guard<mutex> lock(hookMutex);
        return nextHookId++;
    }

    // 创建 ctx 表并推入栈
    static void pushCtxTable(lua_State* L, HkContext* ctx, bool includeRet) {
        lua_newtable(L);
        
        // ctx.addr
        lua_pushinteger(L, static_cast<lua_Integer>(ctx->address));
        lua_setfield(L, -2, "addr");
        
        // ctx.args = {[0]=arg0, [1]=arg1, ...}
        lua_newtable(L);
        for (int i = 0; i < 8; i++) {
            lua_pushinteger(L, static_cast<lua_Integer>(ctx->args[i]));
            lua_rawseti(L, -2, i);
        }
        lua_setfield(L, -2, "args");
        
        // ctx.ret
        if (includeRet) {
            lua_pushinteger(L, static_cast<lua_Integer>(ctx->returnValue));
            lua_setfield(L, -2, "ret");
        }
        
        // ctx.skip
        lua_pushboolean(L, ctx->skipOriginal);
        lua_setfield(L, -2, "skip");
    }

    // 从栈顶的 ctx 表读取修改
    static void pullCtxTable(lua_State* L, HkContext* ctx, bool includeRet) {
        if (!lua_istable(L, -1)) return;
        
        // 读取 args
        lua_getfield(L, -1, "args");
        if (lua_istable(L, -1)) {
            for (int i = 0; i < 8; i++) {
                lua_rawgeti(L, -1, i);
                if (lua_isinteger(L, -1)) {
                    ctx->args[i] = static_cast<uintptr_t>(lua_tointeger(L, -1));
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
        
        // 读取 skip
        lua_getfield(L, -1, "skip");
        if (lua_isboolean(L, -1)) {
            ctx->skipOriginal = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);
        
        // 读取 ret
        if (includeRet) {
            lua_getfield(L, -1, "ret");
            if (lua_isinteger(L, -1)) {
                ctx->returnValue = static_cast<uintptr_t>(lua_tointeger(L, -1));
            }
            lua_pop(L, 1);
        }
    }

    // 执行 Lua 字符串代码 - 线程安全
    static bool executeLuaCode(const string& code, HkContext* ctx, bool isLeave) {
        if (code.empty() || !G_LUA || !ctx) return false;
        
        // 加锁保护 Lua 执行
        lock_guard<recursive_mutex> lock(luaMutex);
        
        // 包装代码为函数: function(ctx) <code> return ctx end
        string wrapped = fmt::format(
            "return function(ctx) {} return ctx end", code);
        
        if (luaL_dostring(G_LUA, wrapped.c_str()) != LUA_OK) {
            const char* err = lua_tostring(G_LUA, -1);
            console->error("hk compile error: {}", err ? err : "unknown");
            lua_pop(G_LUA, 1);
            return false;
        }
        
        // 栈顶是编译后的函数，推入 ctx 表作为参数
        pushCtxTable(G_LUA, ctx, isLeave);
        
        if (lua_pcall(G_LUA, 1, 1, 0) != LUA_OK) {
            const char* err = lua_tostring(G_LUA, -1);
            console->error("hk exec error: {}", err ? err : "unknown");
            lua_pop(G_LUA, 1);
            return false;
        }
        
        // 如果返回了表，读取修改
        if (lua_istable(G_LUA, -1)) {
            pullCtxTable(G_LUA, ctx, isLeave);
        }
        lua_pop(G_LUA, 1);
        
        return true;
    }

public:
    void nop(PTR ptr) {
        if (!ptr) {
            console->error("hk.nop: invalid address");
            return;
        }

        console->info("hk.nop -> {:#x}", ptr);
        
        void* targetAddr = reinterpret_cast<void*>(ptr);
        
        // NOP hook - 直接返回 0，不调用原函数
        auto nopFunc = [](void*, void*, void*, void*) -> void* {
            return nullptr;
        };
        
        void* bridge = REGISTER_LAMBDA(nopFunc);
        if (!bridge) {
            console->error("hk.nop: failed to create bridge function");
            return;
        }
        
        dobby_disable_near_branch_trampoline();
        dobby_dummy_func_t originalFunc = nullptr;
        int result = DobbyHook(targetAddr, reinterpret_cast<dobby_dummy_func_t>(bridge), &originalFunc);

        if (result == 0) {
            lock_guard<mutex> lock(hookMutex);
            auto info = make_shared<HkInfo>();
            info->address = ptr;
            info->original = reinterpret_cast<PTR>(originalFunc);
            info->isActive = true;
            info->hookId = generateHookId();
            info->name = "NOP";
            hookInfoMap[ptr] = info;
            hookIdMap[info->hookId] = ptr;
            console->info("hk.nop: success, id={}", info->hookId);
        } else {
            console->error("hk.nop: failed to hook {:#x}", ptr);
        }
    }

    void unNop(PTR ptr) {
        if (!ptr) {
            console->error("hk.unNop: invalid address");
            return;
        }
        
        console->info("hk.unNop -> {:#x}", ptr);
        
        // 直接使用 DobbyDestroy
        DobbyDestroy(reinterpret_cast<void*>(ptr));

        lock_guard<mutex> lock(hookMutex);
        auto it = hookInfoMap.find(ptr);
        if (it != hookInfoMap.end()) {
            console->info("hk.unNop: removed hook id={}", it->second->hookId);
            hookIdMap.erase(it->second->hookId);
            hookInfoMap.erase(it);
        } else {
            console->warn("hk.unNop: hook not found for {:#x}", ptr);
        }
    }

    /**
     * 安装 Hook
     * 
     * 用法：hk.attach(addr, "print(ctx.args[0])", "print(ctx.ret)")
     * 
     * ctx 表：
     *   ctx.addr  - 地址
     *   ctx.args  - 参数 {[0]=.., [1]=..}
     *   ctx.ret   - 返回值（leave）
     *   ctx.skip  - 设 true 跳过原函数
     * 
     * 注意：原函数地址由 HkInfo 保存，不依赖 HookManager 的静态缓存
     */
    int attach(PTR ptr, const char* enterCode, const char* leaveCode, const char* name = nullptr) {
        if (!ptr) {
            console->error("hk.attach: invalid address");
            return -1;
        }

        string enter = enterCode ? enterCode : "";
        string leave = leaveCode ? leaveCode : "";
        string hookName = name ? name : fmt::format("hk_{:#x}", ptr);

        console->info("hk.attach {:#x} [{}]", ptr, hookName);

        auto info = make_shared<HkInfo>();
        info->address = ptr;
        info->enterCode = enter;
        info->leaveCode = leave;
        info->name = hookName;
        info->hookId = generateHookId();

        void* targetAddr = reinterpret_cast<void*>(ptr);
        dobby_dummy_func_t originalFunc = nullptr;

        // 定义 hook 回调 - 使用 info->original 而不是 SrcCall
        auto hookFunc = [info](void* a, void* b, void* c, void* d) -> void* {
            HkContext ctx = {};
            ctx.address = info->address;
            ctx.args[0] = reinterpret_cast<uintptr_t>(a);
            ctx.args[1] = reinterpret_cast<uintptr_t>(b);
            ctx.args[2] = reinterpret_cast<uintptr_t>(c);
            ctx.args[3] = reinterpret_cast<uintptr_t>(d);
            ctx.skipOriginal = false;
            ctx.returnValue = 0;

            // Enter 回调
            if (!info->enterCode.empty()) {
                try {
                    executeLuaCode(info->enterCode, &ctx, false);
                } catch (...) {
                    // 忽略 Lua 执行异常，避免崩溃
                }
            }

            // 调用原函数 - 使用 info 中保存的原函数地址
            if (!ctx.skipOriginal && info->original) {
                try {
                    using OrigFunc = void*(*)(void*, void*, void*, void*);
                    auto origFn = reinterpret_cast<OrigFunc>(info->original);
                    void* ret = origFn(
                        reinterpret_cast<void*>(ctx.args[0]),
                        reinterpret_cast<void*>(ctx.args[1]),
                        reinterpret_cast<void*>(ctx.args[2]),
                        reinterpret_cast<void*>(ctx.args[3]));
                    ctx.returnValue = reinterpret_cast<uintptr_t>(ret);
                } catch (...) {
                    // 原函数调用失败
                }
            }

            // Leave 回调
            if (!info->leaveCode.empty()) {
                try {
                    executeLuaCode(info->leaveCode, &ctx, true);
                } catch (...) {
                    // 忽略 Lua 执行异常
                }
            }

            return reinterpret_cast<void*>(ctx.returnValue);
        };

        // 使用 LambdaTram 将 lambda 转换为函数指针
        void* bridge = REGISTER_LAMBDA(hookFunc);
        if (!bridge) {
            console->error("hk.attach: failed to create bridge function");
            return -1;
        }

        // 直接调用 DobbyHook，原函数地址保存到 originalFunc
        dobby_disable_near_branch_trampoline();
        int result = DobbyHook(targetAddr, bridge, &originalFunc);

        if (result == 0) {
            // 将原函数地址保存到 info 中，由 Lua 侧管理
            info->original = reinterpret_cast<PTR>(originalFunc);
            info->isActive = true;
            
            lock_guard<mutex> lock(hookMutex);
            hookInfoMap[ptr] = info;
            hookIdMap[info->hookId] = ptr;
            
            console->info("hk.attach: success, id={}, original={:#x}", info->hookId, info->original);
            return info->hookId;
        }
        
        console->error("hk.attach: DobbyHook failed for {:#x}", ptr);
        return -1;
    }

    void detach(PTR ptr) {
        if (!ptr) return;
        console->info("hk.detach {:#x}", ptr);

        DobbyDestroy(reinterpret_cast<void*>(ptr));

        lock_guard<mutex> lock(hookMutex);
        auto it = hookInfoMap.find(ptr);
        if (it != hookInfoMap.end()) {
            hookIdMap.erase(it->second->hookId);
            hookInfoMap.erase(it);
        }
    }

    void detachById(int hookId) {
        PTR addr = 0;
        {
            lock_guard<mutex> lock(hookMutex);
            auto it = hookIdMap.find(hookId);
            if (it != hookIdMap.end()) {
                addr = it->second;
            }
        }
        if (addr) detach(addr);
    }

    int save() {
        lock_guard<mutex> lock(hookMutex);
        savedHooks.clear();
        for (const auto& pair : hookInfoMap) {
            if (pair.second->isActive) {
                savedHooks.push_back(pair.second);
            }
        }
        console->info("hk.save: {} hooks", savedHooks.size());
        return static_cast<int>(savedHooks.size());
    }

    int restore() {
        int restored = 0;
        for (const auto& info : savedHooks) {
            if (!info->enterCode.empty() || !info->leaveCode.empty()) {
                int id = attach(info->address, 
                               info->enterCode.c_str(), 
                               info->leaveCode.c_str(),
                               info->name.c_str());
                if (id > 0) restored++;
            }
        }
        console->info("hk.restore: {} hooks", restored);
        return restored;
    }

    void clear() {
        vector<PTR> addrs;
        {
            lock_guard<mutex> lock(hookMutex);
            for (const auto& pair : hookInfoMap) {
                addrs.push_back(pair.first);
            }
        }
        for (PTR addr : addrs) {
            detach(addr);
        }
        console->info("hk.clear: all hooks removed");
    }

    void list() {
        lock_guard<mutex> lock(hookMutex);
        console->info("=== Hooks ({}) ===", hookInfoMap.size());
        for (const auto& pair : hookInfoMap) {
            const auto& info = pair.second;
            console->info("  [{}] {:#x} - {}", info->hookId, info->address, info->name);
        }
    }

    string info(int hookId) {
        lock_guard<mutex> lock(hookMutex);
        auto it = hookIdMap.find(hookId);
        if (it != hookIdMap.end()) {
            auto hkinfo = hookInfoMap[it->second];
            return fmt::format("ID:{} Addr:{:#x} Original:{:#x} Name:{}", 
                hkinfo->hookId, hkinfo->address, hkinfo->original, hkinfo->name);
        }
        return "not found";
    }

    // 获取原函数地址，供 Lua 侧保存
    PTR getOriginal(int hookId) {
        lock_guard<mutex> lock(hookMutex);
        auto it = hookIdMap.find(hookId);
        if (it != hookIdMap.end()) {
            return hookInfoMap[it->second]->original;
        }
        return 0;
    }

    // 通过地址获取原函数地址
    PTR getOriginalByAddr(PTR addr) {
        lock_guard<mutex> lock(hookMutex);
        auto it = hookInfoMap.find(addr);
        if (it != hookInfoMap.end()) {
            return it->second->original;
        }
        return 0;
    }

    // 直接调用原函数（4参数版本）
    PTR callOriginal(int hookId, PTR a, PTR b, PTR c, PTR d) {
        PTR original = 0;
        {
            lock_guard<mutex> lock(hookMutex);
            auto it = hookIdMap.find(hookId);
            if (it != hookIdMap.end()) {
                original = hookInfoMap[it->second]->original;
            }
        }
        
        if (!original) {
            console->error("hk.callOriginal: hook {} not found or no original", hookId);
            return 0;
        }
        
        using OrigFunc = void*(*)(void*, void*, void*, void*);
        auto fn = reinterpret_cast<OrigFunc>(original);
        return reinterpret_cast<PTR>(fn(
            reinterpret_cast<void*>(a),
            reinterpret_cast<void*>(b),
            reinterpret_cast<void*>(c),
            reinterpret_cast<void*>(d)));
    }

    int count() {
        lock_guard<mutex> lock(hookMutex);
        return static_cast<int>(hookInfoMap.size());
    }
};

// 全局实例
static HkBind hkInstance;

BINDFUNC(hk) {
    // 使用命名空间绑定，支持 hk.nop() 语法
    luabridge::getGlobalNamespace(L)
        .beginNamespace("hk")
        .addFunction("nop", [](PTR ptr) { hkInstance.nop(ptr); })
        .addFunction("unNop", [](PTR ptr) { hkInstance.unNop(ptr); })
        .addFunction("attach", [](PTR ptr, const char* enter, const char* leave) { 
            return hkInstance.attach(ptr, enter, leave); 
        })
        .addFunction("attach4", [](PTR ptr, const char* enter, const char* leave, const char* name) { 
            return hkInstance.attach(ptr, enter, leave, name); 
        })
        .addFunction("detach", [](PTR ptr) { hkInstance.detach(ptr); })
        .addFunction("detachById", [](int id) { hkInstance.detachById(id); })
        .addFunction("save", []() { return hkInstance.save(); })
        .addFunction("restore", []() { return hkInstance.restore(); })
        .addFunction("clear", []() { hkInstance.clear(); })
        .addFunction("list", []() { hkInstance.list(); })
        .addFunction("info", [](int id) { return hkInstance.info(id); })
        .addFunction("count", []() { return hkInstance.count(); })
        // 新增：获取原函数地址，供 Lua 侧管理
        .addFunction("getOriginal", [](int id) { return hkInstance.getOriginal(id); })
        .addFunction("getOriginalByAddr", [](PTR addr) { return hkInstance.getOriginalByAddr(addr); })
        .addFunction("callOriginal", [](int id, PTR a, PTR b, PTR c, PTR d) { 
            return hkInstance.callOriginal(id, a, b, c, d); 
        })
        .endNamespace();
}
