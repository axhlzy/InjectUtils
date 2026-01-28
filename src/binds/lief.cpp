/**
 * @file lief.cpp
 * @brief LIEF 库的 Lua 绑定 - ELF 文件解析和操作
 * 
 * 功能特性：
 * - 解析 ELF 文件结构
 * - 查看导出/导入符号
 * - 查看段和节信息
 * - 查看动态链接信息
 * 
 * Lua 用法：
 *   lief:parse("/path/to/lib.so")     -- 解析 ELF 文件
 *   lief:self()                       -- 解析当前进程
 *   lief:exports("pattern")           -- 搜索导出符号
 *   lief:imports("pattern")           -- 搜索导入符号
 *   lief:sections()                   -- 显示所有节
 *   lief:segments()                   -- 显示所有段
 */

#include "LIEF/ELF.hpp"
#include "bindings.h"

#include <memory>
#include <string>
#include <vector>
#include <algorithm>

class LiefBind {
private:
    std::unique_ptr<LIEF::ELF::Binary> binary_;
    std::string currentPath_;

public:
    /**
     * 解析 ELF 文件
     */
    bool parse(const char* path) {
        if (!path || strlen(path) == 0) {
            console->error("lief.parse: empty path");
            return false;
        }

        binary_ = LIEF::ELF::Parser::parse(path);
        if (!binary_) {
            console->error("lief.parse: failed to parse '{}'", path);
            return false;
        }

        currentPath_ = path;
        console->info("lief: parsed '{}'", path);
        return true;
    }

    /**
     * 解析当前进程
     */
    bool self() {
        return parse(getSelfPath().c_str());
    }

    /**
     * 搜索导出符号
     */
    void exports(const char* pattern) {
        if (!binary_) {
            console->error("lief: no binary loaded, call parse() first");
            return;
        }

        std::string filter = pattern ? pattern : "";
        auto syms = binary_->exported_symbols();
        int count = 0;

        console->info("=== Exported Symbols ({}) ===", currentPath_);
        for (const auto& sym : syms) {
            if (filter.empty() || sym.name().find(filter) != std::string::npos) {
                console->info("  {:#010x}  {:5}  {}", 
                    sym.value(), 
                    sym.size(),
                    sym.name());
                count++;
            }
        }
        console->info("Total: {} symbols", count);
    }

    void exports() {
        exports(nullptr);
    }

    /**
     * 搜索导入符号
     */
    void imports(const char* pattern) {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        std::string filter = pattern ? pattern : "";
        auto syms = binary_->imported_symbols();
        int count = 0;

        console->info("=== Imported Symbols ({}) ===", currentPath_);
        for (const auto& sym : syms) {
            if (filter.empty() || sym.name().find(filter) != std::string::npos) {
                console->info("  {}", sym.name());
                count++;
            }
        }
        console->info("Total: {} symbols", count);
    }

    void imports() {
        imports(nullptr);
    }

    /**
     * 显示所有节
     */
    void sections() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Sections ({}) ===", currentPath_);
        console->info("  {:3}  {:20}  {:16}  {:10}  {:10}", 
            "Idx", "Name", "Address", "Size", "Offset");
        
        int idx = 0;
        for (const auto& sec : binary_->sections()) {
            console->info("  {:3}  {:20}  {:#016x}  {:#010x}  {:#010x}",
                idx++,
                sec.name().substr(0, 20),
                sec.virtual_address(),
                sec.size(),
                sec.offset());
        }
    }

    /**
     * 显示所有段
     */
    void segments() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Segments ({}) ===", currentPath_);
        console->info("  {:3}  {:12}  {:16}  {:16}  {:10}  {:10}  {}", 
            "Idx", "Type", "VirtAddr", "PhysAddr", "FileSize", "MemSize", "Flags");
        
        int idx = 0;
        for (const auto& seg : binary_->segments()) {
            // 获取标志位 - 使用整数值避免与 NDK elf_common.h 宏冲突
            // PF_R=4, PF_W=2, PF_X=1
            auto flags = static_cast<size_t>(seg.flags());
            std::string flagStr;
            if (flags & 4) flagStr += "R";
            if (flags & 2) flagStr += "W";
            if (flags & 1) flagStr += "X";

            console->info("  {:3}  {:12}  {:#016x}  {:#016x}  {:#010x}  {:#010x}  {}",
                idx++,
                LIEF::ELF::to_string(seg.type()),
                seg.virtual_address(),
                seg.physical_address(),
                seg.physical_size(),
                seg.virtual_size(),
                flagStr);
        }
    }

    /**
     * 显示动态条目
     */
    void dynamic() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Dynamic Entries ({}) ===", currentPath_);
        for (const auto& entry : binary_->dynamic_entries()) {
            console->info("  {:20}  {:#x}",
                LIEF::ELF::to_string(entry.tag()),
                entry.value());
        }
    }

    /**
     * 显示依赖库
     */
    void libraries() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Libraries ({}) ===", currentPath_);
        // 从动态条目中获取 NEEDED (DT_NEEDED = 1)
        // 使用整数值避免与 NDK elf_common.h 宏冲突
        for (const auto& entry : binary_->dynamic_entries()) {
            if (static_cast<size_t>(entry.tag()) == 1) {  // DT_NEEDED
                // DynamicEntryLibrary 继承自 DynamicEntry
                if (auto* lib = dynamic_cast<const LIEF::ELF::DynamicEntryLibrary*>(&entry)) {
                    console->info("  {}", lib->name());
                }
            }
        }
    }

    /**
     * 显示重定位信息
     */
    void relocations(size_t limit = 50) {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Relocations ({}) ===", currentPath_);
        size_t count = 0;
        for (const auto& rel : binary_->relocations()) {
            if (count >= limit) {
                console->info("  ... (more relocations)");
                break;
            }
            console->info("  {:#016x}  {:3}  {}",
                rel.address(),
                static_cast<int>(rel.type()),
                rel.has_symbol() ? rel.symbol()->name() : "<no symbol>");
            count++;
        }
    }

    /**
     * 获取 ELF 头信息
     */
    void header() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        const auto& hdr = binary_->header();
        console->info("=== ELF Header ({}) ===", currentPath_);
        
        // 使用 identity_class() 判断位数
        // ELFCLASS64=2, ELFCLASS32=1 - 使用整数避免与 NDK 宏冲突
        auto elfClass = static_cast<size_t>(hdr.identity_class());
        console->info("  Class:       {}", elfClass == 2 ? "ELF64" : "ELF32");
        
        // 使用 identity_data() 判断字节序
        // ELFDATA2LSB=1, ELFDATA2MSB=2 - 使用整数避免与 NDK 宏冲突
        auto elfData = static_cast<size_t>(hdr.identity_data());
        console->info("  Endian:      {}", elfData == 1 ? "Little" : "Big");
        
        console->info("  Type:        {}", LIEF::ELF::to_string(hdr.file_type()));
        console->info("  Machine:     {}", LIEF::ELF::to_string(hdr.machine_type()));
        console->info("  Entry:       {:#x}", hdr.entrypoint());
        console->info("  PH Offset:   {:#x}", hdr.program_headers_offset());
        console->info("  SH Offset:   {:#x}", hdr.section_headers_offset());
        console->info("  PH Count:    {}", hdr.numberof_segments());
        console->info("  SH Count:    {}", hdr.numberof_sections());
    }

    /**
     * 查找符号地址
     */
    PTR findSymbol(const char* name) {
        if (!binary_ || !name) return 0;

        // 先搜索导出符号
        for (const auto& sym : binary_->exported_symbols()) {
            if (sym.name() == name) {
                console->info("lief.findSymbol: {} -> {:#x}", name, sym.value());
                return static_cast<PTR>(sym.value());
            }
        }

        // 再搜索动态符号
        for (const auto& sym : binary_->dynamic_symbols()) {
            if (sym.name() == name) {
                console->info("lief.findSymbol: {} -> {:#x}", name, sym.value());
                return static_cast<PTR>(sym.value());
            }
        }

        console->warn("lief.findSymbol: '{}' not found", name);
        return 0;
    }

    /**
     * 获取节内容
     */
    luabridge::LuaRef sectionData(const char* name, lua_State* L) {
        luabridge::LuaRef result(L);
        if (!binary_ || !name) return result;

        const auto* sec = binary_->get_section(name);
        if (!sec) {
            console->error("lief: section '{}' not found", name);
            return result;
        }

        auto content = sec->content();
        result = luabridge::newTable(L);
        for (size_t i = 0; i < content.size(); i++) {
            result[i + 1] = static_cast<int>(content[i]);
        }
        return result;
    }

    /**
     * 显示摘要信息
     */
    void info() {
        if (!binary_) {
            console->error("lief: no binary loaded");
            return;
        }

        console->info("=== Binary Info ===");
        console->info("  Path:      {}", currentPath_);
        console->info("  Entry:     {:#x}", binary_->entrypoint());
        console->info("  Sections:  {}", binary_->sections().size());
        console->info("  Segments:  {}", binary_->segments().size());
        console->info("  Exports:   {}", binary_->exported_symbols().size());
        console->info("  Imports:   {}", binary_->imported_symbols().size());
    }
};

BINDFUNC(lief) {
    luabridge::getGlobalNamespace(L)
        .beginClass<LiefBind>("LiefBind")
        .addFunction("parse", &LiefBind::parse)
        .addFunction("self", &LiefBind::self)
        .addFunction("exports",
            luabridge::overload<const char*>(&LiefBind::exports),
            luabridge::overload<>(&LiefBind::exports))
        .addFunction("imports",
            luabridge::overload<const char*>(&LiefBind::imports),
            luabridge::overload<>(&LiefBind::imports))
        .addFunction("sections", &LiefBind::sections)
        .addFunction("segments", &LiefBind::segments)
        .addFunction("dynamic", &LiefBind::dynamic)
        .addFunction("libraries", &LiefBind::libraries)
        .addFunction("relocations", &LiefBind::relocations)
        .addFunction("header", &LiefBind::header)
        .addFunction("findSymbol", &LiefBind::findSymbol)
        .addFunction("sectionData", &LiefBind::sectionData)
        .addFunction("info", &LiefBind::info)
        .endClass();

    static LiefBind liefInstance;
    luabridge::setGlobal(L, &liefInstance, "lief");

    // 兼容旧 API
    luabridge::getGlobalNamespace(L)
        .beginNamespace("lief")
        .addFunction("sefsyms", [](const char* pattern) {
            static LiefBind instance;
            instance.self();
            instance.exports(pattern);
        })
        .endNamespace();
}
