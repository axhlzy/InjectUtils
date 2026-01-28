#include "bindings.h"
#include <vector>
#include <algorithm>

// 日志开关 - 设为 true 可排查绑定崩溃问题
inline static bool g_bindShowLog = true;

#define BIND_LOG(fmt, ...) do { if (g_bindShowLog) logd(fmt, ##__VA_ARGS__); } while(0)

void bind_libs(lua_State *L) {
    BIND_LOG("=== Starting bind_libs ===");

    xdl_info_t info;
    void *cache = NULL;
    if (!xdl_addr(reinterpret_cast<void *>(bind_libs), &info, &cache)) {
        logd("[!] INIT LIBS FAILED: xdl_addr failed");
        throw std::runtime_error("[*] INIT LIBS FAILED: xdl_addr");
    }

    BIND_LOG("[*] Module: %s, Base: %p", 
        info.dli_fname ? info.dli_fname : "unknown", info.dli_fbase);

    const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    const char *strtab = nullptr;
    ElfW(Sym) *symtab = nullptr;
    size_t strtab_size = 0;

    // 查找 PT_DYNAMIC 段
    for (int i = 0; i < info.dlpi_phnum; ++i) {
        if (info.dlpi_phdr[i].p_type == PT_DYNAMIC) {
            auto dyn = reinterpret_cast<ElfW(Dyn)*>(base + info.dlpi_phdr[i].p_vaddr);
            while (dyn->d_tag != DT_NULL) {
                switch (dyn->d_tag) {
                    case DT_STRTAB:  strtab = reinterpret_cast<const char*>(base + dyn->d_un.d_ptr); break;
                    case DT_SYMTAB:  symtab = reinterpret_cast<ElfW(Sym)*>(base + dyn->d_un.d_ptr); break;
                    case DT_STRSZ:   strtab_size = dyn->d_un.d_val; break;
                }
                ++dyn;
            }
            break;  // 找到 PT_DYNAMIC 后退出
        }
    }

    if (!strtab || !symtab) {
        logd("[!] Missing SYMTAB or STRTAB");
        throw std::runtime_error("Error: Missing SYMTAB or STRTAB");
    }

    // 收集绑定函数并预分配空间
    std::vector<std::pair<const char*, uintptr_t>> bindFuncs;
    bindFuncs.reserve(32);
    
    const char* symtab_end = reinterpret_cast<const char*>(symtab) + strtab_size;
    for (ElfW(Sym) *sym = symtab; reinterpret_cast<const char*>(sym) < symtab_end; ++sym) {
        if (sym->st_size == 0 || sym->st_name > strtab_size) continue;
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) continue;
        if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL) continue;
        
        const char* name = strtab + sym->st_name;
        size_t len = strlen(name);
        
        // 匹配 reg*_ 模式
        if (len > 4 && name[0] == 'r' && name[1] == 'e' && name[2] == 'g' && name[len-1] == '_') {
            bindFuncs.emplace_back(name, base + sym->st_value);
        }
    }

    // 按名称排序
    std::sort(bindFuncs.begin(), bindFuncs.end(),
        [](const auto& a, const auto& b) { return strcmp(a.first, b.first) < 0; });

    BIND_LOG("[*] Found %zu bind functions", bindFuncs.size());

    // 执行绑定
    using BindFn = void (*)(lua_State*);
    int success = 0, failed = 0;
    const size_t total = bindFuncs.size();
    
    for (size_t i = 0; i < total; ++i) {
        const auto& [name, addr] = bindFuncs[i];
        BIND_LOG("[%zu/%zu] %s", i + 1, total, name);
        
        try {
            reinterpret_cast<BindFn>(addr)(L);
            ++success;
        } catch (const std::exception& e) {
            logw("[FAIL] %s: %s", name, e.what());
            ++failed;
        } catch (...) {
            logw("[FAIL] %s: unknown exception", name);
            ++failed;
        }
    }

    BIND_LOG("=== bind_libs: %d ok, %d fail ===", success, failed);
}