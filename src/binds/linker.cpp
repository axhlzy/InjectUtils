#include "bindings.h"
#include "linker_soinfo.h"
#include "xdl_util.h"

#define LINKERNAME XDL_UTIL_LINKER_BASENAME

#include "rttr/registration"
#include <sstream>

using namespace rttr;

RTTR_REGISTRATION {
    registration::class_<link_map>("link_map")
        .property("l_addr", &link_map::l_addr)
        .property("l_name", &link_map::l_name)
        .property("l_ld", &link_map::l_ld)
        .property("l_next", &link_map::l_next)
        .property("l_prev", &link_map::l_prev);

    registration::class_<soinfo>("soinfo")
        .property("phdr", &soinfo::phdr)
        .property("phnum", &soinfo::phnum)
        .property("base", &soinfo::base)
        .property("size", &soinfo::size)
        .property("dynamic", &soinfo::dynamic)
        .property("next", &soinfo::next)
        // .property("flags_", &soinfo::flags_)
        .property("strtab_", &soinfo::strtab_)
        .property("symtab_", &soinfo::symtab_)
        .property("nbucket_", &soinfo::nbucket_)
        .property("nchain_", &soinfo::nchain_)
        .property("bucket_", &soinfo::bucket_)
        .property("chain_", &soinfo::chain_)
#if defined(USE_RELA)
        .property("plt_rela_", &soinfo::plt_rela_)
        .property("plt_rela_count_", &soinfo::plt_rela_count_)
        .property("rela_", &soinfo::rela_)
        .property("rela_count_", &soinfo::rela_count_)
#else
        .property("plt_rel_", &soinfo::plt_rel_)
        .property("plt_rel_count_", &soinfo::plt_rel_count_)
        .property("rel_", &soinfo::rel_)
        .property("rel_count_", &soinfo::rel_count_)
#endif
        .property("preinit_array_", &soinfo::preinit_array_)
        .property("preinit_array_count_", &soinfo::preinit_array_count_)
        .property("init_array_", &soinfo::init_array_)
        .property("init_array_count_", &soinfo::init_array_count_)
        .property("fini_array_", &soinfo::fini_array_)
        .property("fini_array_count_", &soinfo::fini_array_count_)
        .property("init_func_", &soinfo::init_func_)
        .property("fini_func_", &soinfo::fini_func_)
        .property("ref_count_", &soinfo::ref_count_)
        .property("link_map_head", &soinfo::link_map_head)
        .property("load_bias", &soinfo::load_bias);
}

static void *addr_getSoName = NULL;
static void *addr_get_somain = NULL;

#include "linker_soinfo.h"
using fn_get_soname = const char *(*)(soinfo *);
using fn_get_somain = soinfo *(*)(void);

void init() {
    void *handle = xdl_open(LINKERNAME, XDL_DEFAULT);
    if (handle == nullptr)
        throw std::runtime_error("Open linker failed");

    // get somain
    addr_getSoName = xdl_dsym(handle, "__dl__ZNK6soinfo10get_sonameEv", NULL);
    using fn_get_soname = const char *(*)(soinfo *);
    if (addr_getSoName == nullptr)
        throw std::runtime_error("linker : get_soname failed");

    // get soname
    addr_get_somain = xdl_dsym(handle, "__dl__Z17solist_get_somainv", NULL);
    using fn_get_somain = soinfo *(*)(void);
    if (addr_get_somain == nullptr)
        throw std::runtime_error("linker : get_somain failed");

    xdl_close(handle);
}

// __dl__Z17solist_get_somainv
PTR get_somain() {
    using fn = PTR (*)(void);
    auto ret = reinterpret_cast<fn>(addr_get_somain)();
    console->warn("got [ soinfo* main ] -> {}", (void *)ret);
    return ret;
}

// (soinfo) {
//   phdr = 0x0000007ce3322040
//   phnum = 10
//   base = 536387657728
//   size = 73728
//   dynamic = 0x0000007ce3331e38
//   next = 0x0000007ce5a57eb0
//   flags_ = 1073743169
//   strtab_ = 0x0000007ce3323f94 ""
//   symtab_ = 0x0000007ce33222a8
//   nbucket_ = 0
//   nchain_ = 0
//   bucket_ = 0x0000000000000000
//   chain_ = 0x0000000000000000
//   plt_rela_ = 0x0000007ce3325308
//   plt_rela_count_ = 141
//   rela_ = nullptr
//   rela_count_ = 0
//   preinit_array_ = 0x0000000000000000
//   preinit_array_count_ = 0
//   init_array_ = 0x0000000000000000
//   init_array_count_ = 0
//   fini_array_ = 0x0000007ce3331e28
//   fini_array_count_ = 2
//   init_func_ = 0x0000000000000000
//   fini_func_ = 0x0000000000000000
//   ref_count_ = 0
//   link_map_head = {
//     l_addr = 536387657728
//     l_name = 0x0000007ce5abb840 "/system/lib64/libcutils.so"
//     l_ld = 0x0000007ce3331e38
//     l_next = 0x0000007ce5a57f80
//     l_prev = 0x0000007ce5a57aa0
//   }
//   constructors_called = true
//   load_bias = 536387657728
//   has_DT_SYMBOLIC = false
//   version_ = 6
//   st_dev_ = 64773
//   st_ino_ = 2085
//   children_ = {
//     head_ = 0x0000007ce5b3d660
//     tail_ = 0x0000007ce5b3d700
//   }
//   parents_ = {
//     head_ = 0x0000007ce5b3c4f0
//     tail_ = 0x0000007ce5b51460
//   }
//   file_offset_ = 0
//   rtld_flags_ = 256
//   dt_flags_1_ = 1
//   strtab_size_ = 4777
//   gnu_nbucket_ = 29
//   gnu_bucket_ = 0x0000007ce3323d48
//   gnu_chain_ = 0x0000007ce3323bbc
//   gnu_maskwords_ = 31
//   gnu_shift2_ = 26
//   gnu_bloom_filter_ = 0x0000007ce3323c48
//   local_group_root_ = 0x0000007ce5a57010
//   android_relocs_ = 0x0000007ce3325240 "APS2\f"
//   android_relocs_size_ = 107
//   soname_ = "libcutils.so"
//   realpath_ = "/system/lib64/libcutils.so"
//   versym_ = 0x0000007ce33239b8
//   verdef_ptr_ = 0
//   verdef_cnt_ = 0
//   verneed_ptr_ = 536387664804
//   verneed_cnt_ = 3
//   target_sdk_version_ = 0
//   dt_runpath_ = size=0 {}
//   primary_namespace_ = 0x0000007ce6cd64e0
//   secondary_namespaces_ = (head_ = 0x0000007ce5934370, tail_ = 0x0000007ce5936070)
//   handle_ = 9789523434609700899
//   relr_ = 0x0000007ce33252b0
//   relr_count_ = 11
//   tls_ = nullptr {
//     pointer = nullptr
//   }
//   tlsdesc_args_ = size=0 {}
//   gap_start_ = 536387842048
//   gap_size_ = 0
// }

void disp_soinfo_link() {

    void *handle = xdl_open(LINKERNAME, XDL_DEFAULT);

    auto info = reinterpret_cast<fn_get_somain>(addr_get_somain)();
    auto next = info->next;
    int index = 0;

    do {
        auto soname = reinterpret_cast<fn_get_soname>(addr_getSoName)(info);
        auto phnum = info->phnum;
        auto phdr = info->phdr;
        auto base = info->base;
        auto size = info->size;
        auto dynamic = info->dynamic;
        console->info("{} {} <- {} \n\tphdr : {} phnum : {} \n\tbase : {} | size : {} | dynamic : {}",
                      index++, (void *)info, soname, (void *)phdr, phnum, (void *)base, size, (void *)dynamic);
        info = info->next;
    } while (info != NULL);

    xdl_close(handle);
}

void disp_link_map_head() {
    auto info = reinterpret_cast<fn_get_somain>(addr_get_somain)();
    auto next = info->next;

    auto soname = reinterpret_cast<fn_get_soname>(addr_getSoName)(info);
    auto link_current = info->link_map_head;
    auto load_bias = info->load_bias;
    console->info("{} {} | link_map_head : {} | load_bias : {}\n", (void *)info, soname, (void *)&link, load_bias);

    struct link_map *l_next = &link_current;

    do {
        console->info("l_addr: 0x{:X}, l_name: {} \n\tl_ld: {}, l_next: {}, l_prev: {} }}",
                      l_next->l_addr,
                      l_next->l_name ? l_next->l_name : "null",
                      static_cast<void *>(l_next->l_ld),
                      static_cast<void *>(l_next->l_next),
                      static_cast<void *>(l_next->l_prev));
        l_next = l_next->l_next;
    } while (l_next != NULL);
}

string getExtraInfo(void *ptr) {
    char extraInfo[0x100];
    strcpy(extraInfo, " <NULL> ");
    void *cache;
    Dl_info info;
    if (dladdr(ptr, &info)) {
        const char *name = info.dli_fname;
        if (name != nullptr) {
            const char *last_slash = strrchr(name, '/');
            if (last_slash != NULL)
                name = last_slash + 1;
            uintptr_t offset = (uintptr_t)ptr - (uintptr_t)info.dli_fbase;
            snprintf(extraInfo, 256, "| %p @ %s", (void *)offset, name);
        }
    }
    return string(extraInfo);
}

// std::string getExtraInfo(void *ptr) {
//     string extraInfo = " <NULL> ";
//     void *cache;
//     xdl_info_t info;
//     if (xdl_addr(ptr, &info, &cache)) {
//         string name = info.dli_fname;
//         if (info.dli_fname != nullptr && name.find_last_of('/') != string::npos) {
//             name = name.substr(name.find_last_of('/') + 1);
//         }
//         uintptr_t offset = (uintptr_t)ptr - (uintptr_t)info.dli_fbase;
//         extraInfo = fmt::format("| {} @ {}", (void *)offset, name);
//     }
//     return extraInfo;
// }

#include "utils.h"
std::string get_soinfo(const soinfo *info, const char *appendStart = "\t") {
    if (!info) {
        console->error(fmt::format("{} : soinfo is null", __FUNCTION__));
        return "";
    }

    const char *str_start = reinterpret_cast<const char *>(info->strtab_);
    const char *str_end = nullptr;

    const ElfW(Sym) *symtab_start = nullptr;
    const char *symtab_end = nullptr;
    size_t syment_size = 0;

    for (auto dyn = info->dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
        case DT_SYMTAB:
            symtab_start = reinterpret_cast<const ElfW(Sym) *>(dyn->d_un.d_ptr + info->base);
            break;
        case DT_SYMENT:
            syment_size = dyn->d_un.d_val;
            break;
        case DT_STRSZ:
            str_end = str_start + dyn->d_un.d_val;
            break;
        }
    }

    size_t num_symbols = 0;
    if (syment_size > 0 && symtab_start != nullptr) {
        symtab_end = str_start;
        num_symbols = (symtab_end - (char *)symtab_start) / syment_size;
    }

    std::stringstream os;
    auto st = rttr::type::get(*info);

    for (auto &prop : st.get_properties()) {
        auto name = prop.get_name();
        rttr::variant value = prop.get_value(*info);
        auto const currentType = value.get_type();
        if (currentType == rttr::type::get<const char *>()) {
            const char *cstr = value.get_value<const char *>();
            os << appendStart << name << ": " << (void *)cstr
               << " | " << currentType.get_name().to_string() << std::endl;
        } else if (currentType == rttr::type::get<size_t>()) {
            os << appendStart << name << ": " << value.get_value<size_t>() << std::endl;
        } else {
            os << appendStart << name << ": " << value.get_value<void *>()
               << " | " << currentType.get_name().to_string() << std::endl;
        }
        if (name == "link_map_head") {
            auto link_map_type = rttr::type::get<link_map>();
            auto link_map_head = value.get_value<link_map>();
            for (auto &prop_link : link_map_type.get_properties()) {
                auto name = prop_link.get_name();
                auto value = link_map_type.get_property(name).get_value(link_map_head).get_value<void *>();
                os << appendStart << appendStart << name << ":\t" << value
                   << " | " << currentType.get_name().to_string() << std::endl;
            }
        }
        if (name == "strtab_" || name == "symtab_") {
            if (name == "strtab_") {
                os << appendStart << appendStart
                   << fmt::format("[ {} ~ {} | {} ]",
                                  (void *)str_start, (void *)str_end, (void *)(str_end - str_start))
                   << std::endl;
            }
            if (name == "symtab_") {
                os << appendStart << appendStart
                   << fmt::format("[ {} ~ {} | {} * {} = {} ]",
                                  (void *)symtab_start, (void *)symtab_end, num_symbols, (void *)syment_size, (void *)(num_symbols * syment_size))
                   << std::endl;
            }
            std::string line;
            std::stringstream ss(hexdump(value.get_value<void *>(), 0x50));
            while (std::getline(ss, line, '\n')) {
                os << appendStart << appendStart << line << std::endl;
            }
        } else if (name == "preinit_array_") {
            auto count = st.get_property("preinit_array_count_").get_value(*info).get_value<size_t>();
            if (count > 0) {
                auto preinit_array = st.get_property("preinit_array_").get_value(*info).get_value<void **[]>();
                auto preinit_array_items = *preinit_array;
                for (size_t i = 0; i < (count - 1); i++) {
                    os << appendStart << appendStart
                       << fmt::format("{} {} {}", i, preinit_array_items[i], getExtraInfo(preinit_array_items[i]))
                       << std::endl;
                }
            }
        } else if (name == "init_array_") {
            auto count = st.get_property("init_array_count_").get_value(*info).get_value<size_t>();
            if (count > 0) {
                auto init_array = st.get_property("init_array_").get_value(*info).get_value<void **[]>();
                auto init_array_items = *init_array;
                for (size_t i = 0; i < (count - 1); i++) {
                    os << appendStart << appendStart
                       << fmt::format("{} {} {}", i, init_array_items[i], getExtraInfo(init_array_items[i]))
                       << std::endl;
                }
            }
        } else if (name == "fini_array_") {
            auto count = st.get_property("fini_array_count_").get_value(*info).get_value<size_t>();
            if (count > 0) {
                auto fini_array = st.get_property("fini_array_").get_value(*info).get_value<void **[]>();
                auto fini_array_items = *fini_array;
                for (size_t i = 0; i < (count - 1); i++) {
                    os << appendStart << appendStart
                       << fmt::format("{} {} {}", i, fini_array_items[i], getExtraInfo(fini_array_items[i]))
                       << std::endl;
                }
            }
        }
    }
    return os.str();
}

void show_soinfo(PTR info) {
    console->info(get_soinfo((const soinfo *)info, ""));
}

std::string get_soinfo(PTR info) {
    return get_soinfo((const soinfo *)info);
}

#include <fstream>
#include <iostream>
void show_symtab(const soinfo *si, size_t max_symbols = -1, bool other = false) {
    if (!si || !si->symtab_ || !si->strtab_) {
        std::cerr << "Invalid soinfo pointer or empty symbol/strings tables." << std::endl;
        return;
    }

    const char *symtab_end = reinterpret_cast<const char *>(si->strtab_);
    size_t count = ((uintptr_t)symtab_end - (uintptr_t)si->symtab_) / sizeof(ElfW(Sym));

    std::cout << "\nShowing " << (max_symbols == -1 ? "all" : "up to " + std::to_string(count))
              << " symbols:\n\n";
    std::cout << "Index\tValue\t\tSize\tOther\tNameIndex\t\t\tInfo\t\tName\n\n";

    for (size_t i = 0; i < (max_symbols == -1 ? count : max_symbols); ++i) {
        const ElfW(Sym) *symbol = si->symtab_ + i;
        const char *symbol_name = si->strtab_ + symbol->st_name;

        auto binding = magic_enum::enum_name((ST_BindingType)ELF_ST_BIND(symbol->st_info)).substr(5);
        auto type = magic_enum::enum_name((ST_SymbolType)ELF_ST_TYPE(symbol->st_info)).substr(5);
        auto info = fmt::format(" [ {} | {} ]", binding, type);

        if (other && symbol->st_other == 0)
            continue;

        std::cout << std::setw(5) << i << '\t'
                  << std::setw(10) << (void *)(symbol->st_value) << '\t'
                  << std::setw(4) << (void *)(symbol->st_size) << '\t'
                  << std::setw(4) << (void *)(symbol->st_other) << '\t'
                  << std::setw(9) << symbol->st_name << '\t'
                  << std::setw(10) << static_cast<int>(symbol->st_info) << info << '\t'
                  << symbol_name << '\n';
    }
}

void show_symtab_o(PTR si) {
    show_symtab(reinterpret_cast<const soinfo *>(si), -1, true);
}

void show_symtab(PTR si) {
    show_symtab(reinterpret_cast<const soinfo *>(si), -1);
}

void show_symtab(PTR si, size_t count) {
    show_symtab(reinterpret_cast<const soinfo *>(si), count);
}

#include "Semaphore.hpp"
#include "dobby.h"
#include "utils.h"
#include <stdexcept>

void waitSoLoad(const char *filterSoName) {

    static void *addr_call_constructors = DobbySymbolResolver(LINKERNAME, "__dl__ZN6soinfo17call_constructorsEv");

    if (addr_call_constructors == nullptr)
        throw std::runtime_error("Do not found `__dl__ZN6soinfo17call_constructorsEv`");

    static std::map<std::string, int> map = {};

    HK(addr_call_constructors, [&](const soinfo *info) {
        auto base = info->base;
        string soName = "";
        for (auto dyn = info->dynamic; dyn->d_tag != DT_NULL; ++dyn) {
            if (dyn->d_tag == DT_SONAME) {
                soName = reinterpret_cast<const char *>(info->strtab_ + dyn->d_un.d_val);
                break;
            }
        }
        if (++map[soName] > 1) {
            SrcCall(addr_call_constructors, info);
            return;
        }
        console->info("soinfo::call_constructors ( soinfo : {} | base: {} | soName: {})",
                      (void *)info, (void *)base, soName.c_str());
        if (strlen(filterSoName) != 0 && soName == string(filterSoName)) {
            console->error("STOP AT {}", soName);
            console->info("{}", get_soinfo(info));
            SEMAPHORE_WAIT
        }
        SrcCall(addr_call_constructors, info);
    });
}

void waitSoLoad() {
    waitSoLoad("");
}

void test(PTR ptr, PTR info) {
    HK((void *)ptr, [=](void *a, void *b, void *c, void *d) {
        SrcCall((void *)ptr, a, b, c, d);
        show_soinfo(info);
        show_symtab(info);
    });
}

BINDFUNC(linker) {
    init();
    luabridge::getGlobalNamespace(L)
        .beginNamespace("linker")
        .addFunction("somain", &get_somain)
        .addFunction("disp_soinfo_link", &disp_soinfo_link)
        .addFunction("disp_link_map_head", &disp_link_map_head)
        .addFunction("show_symtab_o", &show_symtab_o)
        .addFunction("get_soinfo",
                     luabridge::overload<PTR>(&get_soinfo),
                     luabridge::overload<const soinfo *, const char *>(&get_soinfo))
        .addFunction("show_soinfo",
                     luabridge::overload<PTR>(&show_soinfo))
        .addFunction("wait",
                     luabridge::overload<>(&waitSoLoad),
                     luabridge::overload<const char *>(&waitSoLoad))
        .addFunction("show_symtab",
                     luabridge::overload<PTR>(&show_symtab),
                     luabridge::overload<PTR, size_t>(&show_symtab))
        .addFunction("test", &test)
        .endNamespace();
}