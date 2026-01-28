/**
 * @file memory.cpp
 * @brief 内存监控和保护的 Lua 绑定
 * 
 * 功能特性：
 * - 内存访问监控 (硬件断点模拟)
 * - 内存保护修改
 * - 内存区域信息查询
 * - 内存搜索
 * 
 * Lua 用法：
 *   mem:watch(addr)           -- 监控内存地址
 *   mem:unwatch(addr)         -- 取消监控
 *   mem:protect(addr, prot)   -- 修改内存保护
 *   mem:info(addr)            -- 查询内存区域信息
 *   mem:search(start, size, pattern)  -- 搜索内存
 */

#include "bindings.h"
#include "Semaphore.hpp"
#include "signal_enum.h"
#include "utils.h"

#include <signal.h>
#include <sys/mman.h>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cstring>

namespace {

struct WatchPoint {
    PTR address;
    size_t size;
    int originalProt;
    bool active;
    std::string name;
};

class MemoryWatcher {
private:
    inline static std::map<PTR, WatchPoint> watchPoints_;
    inline static std::mutex mutex_;
    inline static bool handlerInstalled_ = false;

    static void signalHandler(int sig, siginfo_t* info, void* context) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        void* faultAddr = info->si_addr;
        PTR faultPTR = reinterpret_cast<PTR>(faultAddr);
        
        // 检查是否是我们监控的地址
        for (auto& [addr, wp] : watchPoints_) {
            if (faultPTR >= addr && faultPTR < addr + wp.size) {
                console->warn("=== Memory Watch Triggered ===");
                console->info("  Address:  {:#x}", faultPTR);
                console->info("  Watch:    {} ({:#x})", wp.name, addr);
                console->info("  Signal:   {} ({})", 
                    magic_enum::enum_name(static_cast<SignalE>(sig)),
                    info->si_code);
                
                // 显示寄存器
                showRegs(reinterpret_cast<ucontext_t*>(context));
                
                // 临时恢复权限让程序继续
                SET_MEM_PROTECTION_RWX(faultAddr);
                
                console->info("Waiting... (use cont() to continue)");
                SEMAPHORE_WAIT
                
                return;
            }
        }
        
        // 不是我们的监控点，恢复默认处理
        signal(sig, SIG_DFL);
        raise(sig);
    }

    static void installHandler() {
        if (handlerInstalled_) return;
        
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = signalHandler;
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGBUS, &sa, nullptr);
        
        handlerInstalled_ = true;
    }

public:
    static bool addWatch(PTR addr, size_t size, const char* name) {
        if (!addr) return false;
        
        std::lock_guard<std::mutex> lock(mutex_);
        installHandler();
        
        // 获取页对齐地址 (用于 mprotect)
        size_t pageSize = sysconf(_SC_PAGESIZE);
        (void)pageSize; // 避免未使用警告
        
        WatchPoint wp;
        wp.address = addr;
        wp.size = size;
        wp.active = true;
        wp.name = name ? name : fmt::format("watch_{:#x}", addr);
        
        // 移除写权限触发 SIGSEGV
        SET_MEM_PROTECTION___(addr);
        
        watchPoints_[addr] = wp;
        console->info("mem.watch: {:#x} ({} bytes) - {}", addr, size, wp.name);
        return true;
    }

    static bool removeWatch(PTR addr) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = watchPoints_.find(addr);
        if (it == watchPoints_.end()) {
            console->warn("mem.unwatch: {:#x} not found", addr);
            return false;
        }
        
        // 恢复权限
        SET_MEM_PROTECTION_RWX(reinterpret_cast<void*>(addr));
        
        watchPoints_.erase(it);
        console->info("mem.unwatch: {:#x}", addr);
        return true;
    }

    static void listWatches() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        console->info("=== Memory Watches ({}) ===", watchPoints_.size());
        for (const auto& [addr, wp] : watchPoints_) {
            console->info("  {:#x}  {:6}  {}", addr, wp.size, wp.name);
        }
    }

    static void clearAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& [addr, wp] : watchPoints_) {
            SET_MEM_PROTECTION_RWX(reinterpret_cast<void*>(addr));
        }
        watchPoints_.clear();
        console->info("mem: all watches cleared");
    }
};

} // anonymous namespace

class MemBind {
public:
    /**
     * 添加内存监控
     */
    void watch(PTR addr, size_t size, const char* name) {
        MemoryWatcher::addWatch(addr, size, name);
    }

    void watch(PTR addr, size_t size) {
        watch(addr, size, nullptr);
    }

    void watch(PTR addr) {
        watch(addr, sizeof(void*), nullptr);
    }

    /**
     * 移除内存监控
     */
    void unwatch(PTR addr) {
        MemoryWatcher::removeWatch(addr);
    }

    /**
     * 列出所有监控点
     */
    void list() {
        MemoryWatcher::listWatches();
    }

    /**
     * 清除所有监控
     */
    void clear() {
        MemoryWatcher::clearAll();
    }

    /**
     * 修改内存保护属性
     * @param prot: "r", "rw", "rx", "rwx", "none" 或数字
     */
    bool protect(PTR addr, const char* prot) {
        if (!addr || !prot) return false;

        int protFlags = 0;
        std::string protStr = prot;
        
        if (protStr == "none") {
            protFlags = PROT_NONE;
        } else {
            if (protStr.find('r') != std::string::npos) protFlags |= PROT_READ;
            if (protStr.find('w') != std::string::npos) protFlags |= PROT_WRITE;
            if (protStr.find('x') != std::string::npos) protFlags |= PROT_EXEC;
        }

        size_t pageSize = sysconf(_SC_PAGESIZE);
        PTR pageAddr = addr & ~(pageSize - 1);
        
        if (mprotect(reinterpret_cast<void*>(pageAddr), pageSize, protFlags) == 0) {
            console->info("mem.protect: {:#x} -> {}", addr, prot);
            return true;
        }
        
        console->error("mem.protect: failed ({})", strerror(errno));
        return false;
    }

    bool protect(PTR addr, int prot) {
        if (!addr) return false;

        size_t pageSize = sysconf(_SC_PAGESIZE);
        PTR pageAddr = addr & ~(pageSize - 1);
        
        if (mprotect(reinterpret_cast<void*>(pageAddr), pageSize, prot) == 0) {
            console->info("mem.protect: {:#x} -> {}", addr, prot);
            return true;
        }
        
        console->error("mem.protect: failed");
        return false;
    }

    /**
     * 查询内存区域信息
     */
    void info(PTR addr) {
        if (!addr) {
            console->error("mem.info: invalid address");
            return;
        }

        // 读取 /proc/self/maps
        std::ifstream maps("/proc/self/maps");
        std::string line;
        
        while (std::getline(maps, line)) {
            uintptr_t start, end;
            char perms[5];
            
            if (sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (addr >= start && addr < end) {
                    console->info("=== Memory Region ===");
                    console->info("  Address: {:#x}", addr);
                    console->info("  Range:   {:#x} - {:#x}", start, end);
                    console->info("  Size:    {:#x} ({} KB)", end - start, (end - start) / 1024);
                    console->info("  Perms:   {}", perms);
                    console->info("  Offset:  {:#x}", addr - start);
                    console->info("  Line:    {}", line);
                    return;
                }
            }
        }
        
        console->warn("mem.info: {:#x} not found in maps", addr);
    }

    /**
     * 搜索内存中的字节模式
     */
    PTR search(PTR start, size_t size, const char* hexPattern) {
        if (!start || !hexPattern) return 0;

        // 解析十六进制模式 (支持 "90 90 ??" 格式)
        std::vector<uint8_t> pattern;
        std::vector<bool> mask;
        
        std::string patStr = hexPattern;
        std::istringstream iss(patStr);
        std::string byte;
        
        while (iss >> byte) {
            if (byte == "??" || byte == "?") {
                pattern.push_back(0);
                mask.push_back(false);
            } else {
                pattern.push_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)));
                mask.push_back(true);
            }
        }

        if (pattern.empty()) return 0;

        // 搜索
        const uint8_t* data = reinterpret_cast<const uint8_t*>(start);
        for (size_t i = 0; i <= size - pattern.size(); i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (mask[j] && data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                PTR result = start + i;
                console->info("mem.search: found at {:#x}", result);
                return result;
            }
        }

        console->info("mem.search: pattern not found");
        return 0;
    }

    /**
     * 搜索所有匹配
     */
    luabridge::LuaRef searchAll(PTR start, size_t size, const char* hexPattern, lua_State* L) {
        luabridge::LuaRef results = luabridge::newTable(L);
        if (!start || !hexPattern) return results;

        std::vector<uint8_t> pattern;
        std::vector<bool> mask;
        
        std::string patStr = hexPattern;
        std::istringstream iss(patStr);
        std::string byte;
        
        while (iss >> byte) {
            if (byte == "??" || byte == "?") {
                pattern.push_back(0);
                mask.push_back(false);
            } else {
                pattern.push_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)));
                mask.push_back(true);
            }
        }

        if (pattern.empty()) return results;

        const uint8_t* data = reinterpret_cast<const uint8_t*>(start);
        int idx = 1;
        
        for (size_t i = 0; i <= size - pattern.size(); i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (mask[j] && data[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                results[idx++] = static_cast<lua_Integer>(start + i);
            }
        }

        console->info("mem.searchAll: found {} matches", idx - 1);
        return results;
    }

    /**
     * 获取页大小
     */
    size_t pageSize() {
        return sysconf(_SC_PAGESIZE);
    }

    /**
     * 对齐到页边界
     */
    PTR pageAlign(PTR addr) {
        size_t ps = pageSize();
        return addr & ~(ps - 1);
    }
};

BINDFUNC(memory) {
    luabridge::getGlobalNamespace(L)
        .beginClass<MemBind>("MemBind")
        .addFunction("watch",
            luabridge::overload<PTR, size_t, const char*>(&MemBind::watch),
            luabridge::overload<PTR, size_t>(&MemBind::watch),
            luabridge::overload<PTR>(&MemBind::watch))
        .addFunction("unwatch", &MemBind::unwatch)
        .addFunction("list", &MemBind::list)
        .addFunction("clear", &MemBind::clear)
        .addFunction("protect",
            luabridge::overload<PTR, const char*>(&MemBind::protect),
            luabridge::overload<PTR, int>(&MemBind::protect))
        .addFunction("info", &MemBind::info)
        .addFunction("search", &MemBind::search)
        .addFunction("searchAll", &MemBind::searchAll)
        .addFunction("pageSize", &MemBind::pageSize)
        .addFunction("pageAlign", &MemBind::pageAlign)
        .endClass();

    static MemBind memInstance;
    luabridge::setGlobal(L, &memInstance, "mem");

    // 全局快捷函数 (使用 lambda)
    luabridge::getGlobalNamespace(L)
        .addFunction("watch", [](PTR addr) { memInstance.watch(addr); });
}
