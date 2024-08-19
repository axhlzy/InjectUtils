#include "KittyMemoryMgr.hpp"
#include "bindings.h"
#include "magic_enum.hpp"
#include <LIEF/LIEF.hpp>
#include <cxxabi.h>

using namespace LIEF;

extern KittyMemoryMgr kittyMemMgr;

void iterSyms(const char *mdName) {
    if (!mdName) {
        console->error("[*] Module name is null");
        return;
    }
    auto scanner = kittyMemMgr.getMemElf(mdName);
    if (!scanner.isValid()) {
        console->error("[*] scanner : Elf is invalid");
        return;
    }
    //  scanner.symbols();
    auto syms = scanner.symbols();
    int i = -1;

    for (std::pair<uintptr_t, std::string> &sym : syms) {
        console->info("[{}] {:p} -> {}\n", i, (void *)sym.first, sym.second);
        // demangle -> extern _LIBCXXABI_FUNC_VIS char *__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length, int *status);
        try {
            console->info("\t\t{}", abi::__cxa_demangle(sym.second.c_str(), nullptr, nullptr, nullptr));
        } catch (const std::exception &e) {
            console->error("{}", e.what());
        }
    }
}

void findsyms(const char *mdName, const char *symName) {
    if (!mdName) {
        console->error("[*] Module name is null");
        return;
    }
    auto scanner = kittyMemMgr.getMemElf(mdName);
    if (!scanner.isValid()) {
        console->error("[*] scanner : Elf is invalid");
        return;
    }
    auto syms = scanner.symbols();
    int i = -1;

    for (std::pair<uintptr_t, std::string> &sym : syms) {
        const char *demangled = abi::__cxa_demangle(sym.second.c_str(), nullptr, nullptr, nullptr);
        if (sym.second.find(symName) != std::string::npos || (demangled && std::string(demangled).find(symName) != std::string::npos)) {
            console->info("[{}] {} -> {}\n", i, (void *)sym.first, sym.second);
            try {
                console->info("{}", demangled);
            } catch (const std::exception &e) {
                console->error("{}", e.what());
            }
        }
    }
}

std::string demangleName(const std::string &mangled_name) {
    int status;
    char *demangled = abi::__cxa_demangle(mangled_name.c_str(), nullptr, nullptr, &status);

    std::string result; // 用于储存和返回结果
    if (status == 0 && demangled) {
        result = demangled; // 如果解码成功，复制结果到字符串
    } else {
        result = "Failed to demangle name"; // 解码失败，返回错误信息
    }

    std::free(demangled); // 释放由__cxa_demangle分配的内存

    return result;
}

BINDFUNC(base) {
    // .addFunction("xdl_sym",
    //              luabridge::overload<PTR, const char *>(&xdl_bind::_xdl_sym),
    //              luabridge::overload<PTR, const char *, ElfW(Sym) *>(&xdl_bind::_xdl_sym))
    luabridge::getGlobalNamespace(L)
        .addFunction("demangleName", demangleName)
        .addFunction("syms", luabridge::overload<const char *>(&iterSyms))
        .addFunction("syms", luabridge::overload<>(*[]() { iterSyms("libil2cpp.so"); }))
        .addFunction("findsyms", luabridge::overload<const char *, const char *>(&findsyms));
}