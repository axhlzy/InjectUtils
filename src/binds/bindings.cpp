#include "bindings.h"

void bind_libs(lua_State *L) {

    xdl_info_t info;
    void *cache = NULL;
    if (!xdl_addr(reinterpret_cast<void *>(bind_libs), &info, &cache))
        throw std::runtime_error(fmt::format("[*] INIT libs failed @ {}\n", __LINE__));

    static const uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
    static const char *strtab = NULL;
    static ElfW(Sym) *symtab = NULL;
    static size_t strtab_size = 0;

    for (int i = 0; i < info.dlpi_phnum; ++i) {
        const ElfW(Phdr) &phdr = info.dlpi_phdr[i];
        if (phdr.p_type == PT_DYNAMIC) {
            auto dyn = (ElfW(Dyn) *)(base + phdr.p_vaddr);
            for (; dyn->d_tag != DT_NULL; ++dyn) {
                if (dyn->d_tag == DT_STRTAB) {
                    strtab = (const char *)(base + dyn->d_un.d_ptr);
                } else if (dyn->d_tag == DT_SYMTAB) {
                    symtab = (ElfW(Sym) *)(base + dyn->d_un.d_ptr);
                } else if (dyn->d_tag == DT_STRSZ) {
                    strtab_size = dyn->d_un.d_val;
                }
            }
        }
    }

    if (!strtab || !symtab)
        throw std::runtime_error(fmt::format("Error: Missing SYMTAB or STRTAB"));

    for (ElfW(Sym) *sym = symtab; (char *)sym < (char *)symtab + strtab_size; ++sym) {
        if (sym->st_size != 0 &&
            sym->st_name <= strtab_size &&
            ELF64_ST_TYPE(sym->st_info) == STT_FUNC &&
            ELF64_ST_BIND(sym->st_info) == STB_GLOBAL) {
            auto name = std::string(reinterpret_cast<const char *>(strtab + sym->st_name));
            if (!name.empty() &&
                name.find("reg") == 0 &&
                name.rfind("_") == name.size() - 1) {
                uintptr_t target = base + sym->st_value;
                // console->info("calling {} @ {} | {}", name, (void *)target, sym->st_size);
                using fn = void (*)(lua_State *);
                fn f = reinterpret_cast<fn>(target);
                try {
                    f(L);
                    console->info("[*] luabridge bind {}", name);
                } catch (const std::exception &e) {
                    console->error("{}", e.what());
                }
            }
        }
    }
}