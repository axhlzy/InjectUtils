#include "LIEF/ELF.hpp"
#include "bindings.h"

void lief_open_self(const char *symName) {
    auto lief = LIEF::ELF::Parser::parse(get_self_path());
    if (lief == nullptr) {
        console->error("LIEF: Failed to parse self");
        return;
    }
    auto syms = lief->exported_symbols();
    for (auto &sym : syms) {
        if (sym.name().find(symName) != std::string::npos) {
            console->info("LIEF: Exported symbol: {}", sym.name());
        }
    }
}

void reg_lief(lua_State *L) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("lief")
        .addFunction("sefsyms", &lief_open_self)
        .endNamespace();

    console->info("[*] luabridge bind {}", "lief");
}