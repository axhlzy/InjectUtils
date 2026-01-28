/**
 * @file global.cpp
 * @brief 全局工具函数的 Lua 绑定
 * 
 * 功能特性：
 * - 内存查看和写入 (x, w)
 * - 线程列表和状态查看
 * - Lua 对象遍历工具
 * - 系统命令快捷方式
 * - 类型转换工具
 * 
 * Lua 用法：
 *   x(addr)              -- 查看内存 (默认 0x20 字节)
 *   x(addr, 0x100)       -- 查看指定大小
 *   w(addr, value)       -- 写入数值
 *   w(addr, "string")    -- 写入字符串
 *   listThreads()        -- 列出当前进程线程
 *   ptr(0x12345678)      -- 数字转指针
 *   hex(255)             -- 数字转十六进制字符串
 */

#include "bindings.h"
#include "utils.h"

#include <dirent.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <iomanip>
#include <sstream>

namespace {

constexpr size_t DEFAULT_DUMP_SIZE = 0x20;
constexpr size_t MAX_DUMP_SIZE = 0x10000;
constexpr int LUA_BUF_SIZE = 2048;

} // anonymous namespace

class GlobalBind {
public:
    /**
     * 十六进制内存查看
     */
    void hexdump(PTR addr, size_t size = DEFAULT_DUMP_SIZE) {
        if (!addr) {
            console->error("x: invalid address");
            return;
        }
        if (size > MAX_DUMP_SIZE) {
            console->warn("x: size capped to {:#x}", MAX_DUMP_SIZE);
            size = MAX_DUMP_SIZE;
        }

        std::string header = fmt::format("[ {:#x} -> {:#x} | {:#x} bytes ]",
            addr, addr + size, size);
        std::string dump = ::hexdump(reinterpret_cast<const void*>(addr), size);
        console->info("{}\n{}", header, dump);
    }

    void hexdump(PTR addr) {
        hexdump(addr, DEFAULT_DUMP_SIZE);
    }

    /**
     * 写入内存 - 数值
     */
    void writeValue(PTR addr, uintptr_t value) {
        if (!addr) {
            console->error("w: invalid address");
            return;
        }
        *reinterpret_cast<uintptr_t*>(addr) = value;
        console->info("w: {:#x} <- {:#x}", addr, value);
    }

    /**
     * 写入内存 - 字符串
     */
    void writeString(PTR addr, const char* str) {
        if (!addr) {
            console->error("w: invalid address");
            return;
        }
        if (!str) {
            console->error("w: null string");
            return;
        }
        std::strcpy(reinterpret_cast<char*>(addr), str);
        console->info("w: {:#x} <- \"{}\"", addr, str);
    }

    /**
     * 写入内存 - 字节数组
     */
    void writeBytes(PTR addr, luabridge::LuaRef bytesTable, lua_State* L) {
        if (!addr) {
            console->error("w: invalid address");
            return;
        }
        if (!bytesTable.isTable()) {
            console->error("w: expected byte table");
            return;
        }

        std::vector<uint8_t> bytes;
        for (int i = 1; ; i++) {
            luabridge::LuaRef val = bytesTable[i];
            if (val.isNil()) break;
            auto result = val.cast<int>();
            if (result) {
                bytes.push_back(static_cast<uint8_t>(result.value()));
            }
        }

        if (bytes.empty()) {
            console->error("w: empty byte table");
            return;
        }

        std::memcpy(reinterpret_cast<void*>(addr), bytes.data(), bytes.size());
        console->info("w: {:#x} <- {} bytes", addr, bytes.size());
    }

    /**
     * 读取内存值
     */
    uintptr_t readValue(PTR addr) {
        if (!addr) {
            console->error("r: invalid address");
            return 0;
        }
        return *reinterpret_cast<uintptr_t*>(addr);
    }

    /**
     * 读取字符串
     */
    std::string readString(PTR addr, size_t maxLen) {
        if (!addr) return "";
        const char* str = reinterpret_cast<const char*>(addr);
        return std::string(str, strnlen(str, maxLen));
    }

    std::string readString(PTR addr) {
        return readString(addr, 256);
    }

    /**
     * 列出线程
     */
    void listThreads(pid_t pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/task/";
        DIR* dir = opendir(path.c_str());
        
        if (!dir) {
            console->error("listThreads: cannot open {}", path);
            return;
        }

        console->info("=== Threads (pid: {}) ===", pid);
        struct dirent* ent;
        int count = 0;
        
        while ((ent = readdir(dir)) != nullptr) {
            std::string tid(ent->d_name);
            if (tid != "." && tid != "..") {
                int tidNum = std::stoi(tid);
                console->info("  [{}] {} - {}", count++, tidNum, getThreadName(tidNum));
            }
        }
        closedir(dir);
    }

    void listThreads() {
        listThreads(getpid());
    }

    /**
     * 获取线程状态
     */
    void threadStat(pid_t tid) {
        console->info("{}", getStat(tid));
    }

    /**
     * 数字转十六进制字符串
     */
    std::string toHex(uintptr_t value) {
        return fmt::format("{:#x}", value);
    }

    /**
     * 比较内存
     */
    bool memCompare(PTR addr1, PTR addr2, size_t size) {
        if (!addr1 || !addr2) return false;
        return std::memcmp(
            reinterpret_cast<void*>(addr1),
            reinterpret_cast<void*>(addr2),
            size) == 0;
    }

    /**
     * 内存搜索 (简单模式)
     */
    PTR memSearch(PTR start, size_t range, uintptr_t value) {
        if (!start) return 0;
        
        uintptr_t* ptr = reinterpret_cast<uintptr_t*>(start);
        uintptr_t* end = reinterpret_cast<uintptr_t*>(start + range);
        
        while (ptr < end) {
            if (*ptr == value) {
                return reinterpret_cast<PTR>(ptr);
            }
            ptr++;
        }
        return 0;
    }

    /**
     * 填充内存
     */
    void memFill(PTR addr, size_t size, uint8_t value) {
        if (!addr) {
            console->error("memFill: invalid address");
            return;
        }
        std::memset(reinterpret_cast<void*>(addr), value, size);
        console->info("memFill: {:#x} filled with {:#02x} ({} bytes)", addr, value, size);
    }

    /**
     * 复制内存
     */
    void memCopy(PTR dest, PTR src, size_t size) {
        if (!dest || !src) {
            console->error("memCopy: invalid address");
            return;
        }
        std::memcpy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(src), size);
        console->info("memCopy: {:#x} <- {:#x} ({} bytes)", dest, src, size);
    }
};

// Lua 对象遍历辅助函数
static void loopObject(lua_State* L, const char* objName) {
    const char* code = R"(
        local function printFunctions(obj, depth)
            depth = depth or 0
            local indent = string.rep("  ", depth)
            for key, value in pairs(obj) do
                if type(value) == "function" then
                    print(indent .. "[F] " .. tostring(key))
                elseif type(value) == "table" then
                    print(indent .. "[T] " .. tostring(key))
                    printFunctions(value, depth + 1)
                else
                    print(indent .. "[" .. type(value):sub(1,1):upper() .. "] " .. tostring(key) .. " = " .. tostring(value))
                end
            end
        end
        printFunctions(%s)
    )";
    
    char buf[LUA_BUF_SIZE];
    snprintf(buf, sizeof(buf), code, objName);
    luaL_dostring(L, buf);
}

static void loopAll(lua_State* L, const char* objName) {
    const char* code = R"(
        for key, value in pairs(%s) do
            print(type(value), key, "=", tostring(value))
        end
    )";
    
    char buf[LUA_BUF_SIZE];
    snprintf(buf, sizeof(buf), code, objName);
    luaL_dostring(L, buf);
}

BINDFUNC(global) {
    // 全局实例 (需要在前面定义以便 lambda 捕获)
    static GlobalBind globalInstance;

    // 注册类
    luabridge::getGlobalNamespace(L)
        .beginClass<GlobalBind>("GlobalBind")
        .addFunction("x",
            luabridge::overload<PTR, size_t>(&GlobalBind::hexdump),
            luabridge::overload<PTR>(&GlobalBind::hexdump))
        .addFunction("w",
            luabridge::overload<PTR, uintptr_t>(&GlobalBind::writeValue),
            luabridge::overload<PTR, const char*>(&GlobalBind::writeString))
        .addFunction("wbytes", &GlobalBind::writeBytes)
        .addFunction("r", &GlobalBind::readValue)
        .addFunction("rs", 
            luabridge::overload<PTR, size_t>(&GlobalBind::readString),
            luabridge::overload<PTR>(&GlobalBind::readString))
        .addFunction("threads",
            luabridge::overload<pid_t>(&GlobalBind::listThreads),
            luabridge::overload<>(&GlobalBind::listThreads))
        .addFunction("threadStat", &GlobalBind::threadStat)
        .addFunction("hex", &GlobalBind::toHex)
        .addFunction("memcmp", &GlobalBind::memCompare)
        .addFunction("memsearch", &GlobalBind::memSearch)
        .addFunction("memfill", &GlobalBind::memFill)
        .addFunction("memcpy", &GlobalBind::memCopy)
        .endClass();

    luabridge::setGlobal(L, &globalInstance, "g");

    // 全局快捷函数 (使用 lambda 避免 overload 实例参数问题)
    luabridge::getGlobalNamespace(L)
        // 内存操作
        .addFunction("x", [](PTR addr, size_t size) { globalInstance.hexdump(addr, size); })
        .addFunction("w", [](PTR addr, uintptr_t val) { globalInstance.writeValue(addr, val); })
        .addFunction("r", [](PTR addr) { return globalInstance.readValue(addr); })
        .addFunction("rs", [](PTR addr) { return globalInstance.readString(addr); })
        
        // 线程
        .addFunction("listThreads", []() { globalInstance.listThreads(); })
        .addFunction("getStat", [](pid_t tid) { globalInstance.threadStat(tid); })
        
        // 工具
        .addFunction("hex", [](uintptr_t v) { return globalInstance.toHex(v); })
        .addFunction("ptr", [](uintptr_t v) -> PTR { return static_cast<PTR>(v); })
        
        // 系统命令
        .addFunction("clear", []() { system("clear"); })
        .addFunction("ls", []() { system("ls -la"); })
        .addFunction("pwd", []() { 
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) console->info("{}", cwd);
        })
        .addFunction("q", []() { exit(0); })
        .addFunction("exit", []() { exit(0); })
        
        // Lua 对象遍历
        .addFunction("loop", [=](const char* obj) { loopObject(L, obj); })
        .addFunction("loopAll", [=](const char* obj) { loopAll(L, obj); })
        
        // 帮助
        .addFunction("help", []() {
            console->info("=== Global Commands ===");
            console->info("  x(addr [,size])    - hexdump memory");
            console->info("  w(addr, value)     - write value/string");
            console->info("  r(addr)            - read value");
            console->info("  rs(addr)           - read string");
            console->info("  listThreads()      - list threads");
            console->info("  hex(num)           - to hex string");
            console->info("  ptr(num)           - to pointer");
            console->info("  loop(obj)          - iterate lua object");
            console->info("  clear/ls/pwd/q     - system commands");
        });
}
