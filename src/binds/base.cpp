#include "KittyMemoryMgr.hpp"
#include "bindings.h"
#include "magic_enum.hpp"
#include <LIEF/LIEF.hpp>
#include <cxxabi.h>

using namespace LIEF;

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
    //  scanner.symbols();
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

void reg_base(lua_State *L) {

    // .addFunction("xdl_sym",
    //              luabridge::overload<PTR, const char *>(&xdl_bind::_xdl_sym),
    //              luabridge::overload<PTR, const char *, ElfW(Sym) *>(&xdl_bind::_xdl_sym))

    luabridge::getGlobalNamespace(L)
        .addFunction("syms", luabridge::overload<const char *>(&iterSyms));

    luabridge::getGlobalNamespace(L)
        .addFunction("syms", luabridge::overload<>(*[]() { iterSyms("libil2cpp.so"); }));

    luabridge::getGlobalNamespace(L)
        .addFunction("findsyms", luabridge::overload<const char *, const char *>(&findsyms));

    console->info("[*] luabridge bind {}", "base");
}