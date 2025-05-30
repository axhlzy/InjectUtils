#include "xdl.h"
#include "bindings.h"

#include "rttr/registration"
#include <sstream>

using namespace rttr;

RTTR_REGISTRATION {
    registration::class_<xdl_info_t>("xdl_info_t")
        .property("dli_fname", &xdl_info_t::dli_fname)
        .property("dli_fbase", &xdl_info_t::dli_fbase)
        .property("dli_sname", &xdl_info_t::dli_sname)
        .property("dli_saddr", &xdl_info_t::dli_saddr)
        .property("dli_ssize", &xdl_info_t::dli_ssize)
        .property("dlpi_phdr", &xdl_info_t::dlpi_phdr)
        .property("dlpi_phnum", &xdl_info_t::dlpi_phnum);
}

void parseInfo(void *handle);
const char *XdlInfoToString(xdl_info_t *info);

void info_self() {
    auto handle = xdl_open(EXEC_NAME, XDL_DEFAULT);
    if (handle == nullptr) {
        console->info("xdl_open failed\n");
    }
    parseInfo(handle);
}

void info(PTR p) {
    void *handle = reinterpret_cast<void *>(p);
    if (handle == nullptr) {
        console->info("xdl_open failed\n");
    }
    parseInfo(handle);
}

void info(const char *lib) {
    if (lib == "")
        return info_self();
    auto handle = xdl_open(lib, XDL_DEFAULT);
    if (handle == nullptr) {
        console->info("xdl_open failed\n");
    }
    parseInfo(handle);
}

void addressInfo(PTR p) {
    xdl_info_t info;
    auto handle = xdl_open(EXEC_NAME, XDL_DEFAULT);
    if (handle == nullptr) {
        console->info("xdl_open failed\n");
        return;
    }
    xdl_info(handle, XDL_DI_DLINFO, &info);
    xdl_addr((void *)p, &info, nullptr);
    console->info("xdl_info: {}\n", (void *)&info);
    xdl_close(handle);
}

void iteratePhdr() {
    auto handle = xdl_open(EXEC_NAME, XDL_DEFAULT);
    xdl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t size, void *data) -> int {
            console->info("dlpi_name: {}\n\tdlpi_addr: {}\n\tdlpi_phdr: {}\n\tdlpi_phnum: {}",
                          info->dlpi_name,
                          (void *)info->dlpi_addr,
                          (void *)info->dlpi_phdr,
                          (int)info->dlpi_phnum);
            return 0;
        },
        nullptr, XDL_DEFAULT);
    xdl_close(handle);
}

// void *xdl_open(const char *filename, int flags)
void _xdl_open(const char *filename, int flags) {
    auto handle = xdl_open(filename, flags);
    console->info("xdl_open ->  {}", handle);
}

void _xdl_open(const char *filename) {
    _xdl_open(filename, RTLD_LAZY);
}

// void xdl_close(void *handle);
void _xdl_close(PTR handle) {
    auto ret = xdl_close(reinterpret_cast<void *>(handle));
    console->info("xdl_close ->  {}", ret);
}

// void *xdl_sym(void *handle, const char *symbol, ElfW(Sym) *out_sym)
void _xdl_sym(PTR handle, const char *symbol, ElfW(Sym) *out_sym = nullptr) {
    assert(handle != 0);
    auto sym = xdl_sym(reinterpret_cast<void *>(handle), symbol, out_sym);
    console->info("xdl_dsym -> {}", sym);
}

void _xdl_sym(PTR handle, const char *symbol) {
    assert(handle != 0);
    _xdl_sym(handle, symbol, nullptr);
}

// void *xdl_dsym(void *handle, const char *symbol, ElfW(Sym) *out_sym)
void _xdl_dsym(PTR handle, const char *symbol, PTR out_sym = 0) {
    assert(handle != 0);
    auto sym = xdl_dsym(reinterpret_cast<void *>(handle), symbol, (ElfW(Sym) *)out_sym);
    console->info("xdl_dsym -> {}", sym);
}

void _xdl_dsym(PTR handle, const char *symbol) {
    _xdl_dsym(handle, symbol, 0);
}

void iterate_phdr() {
    auto handle = xdl_open(EXEC_NAME, XDL_DEFAULT);
    xdl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t size, void *data) -> int {
            console->info("dlpi_name: {}\n\tdlpi_addr: {}\n\tdlpi_phdr: {}\n\tdlpi_phnum: {}",
                          info->dlpi_name,
                          (void *)info->dlpi_addr,
                          (void *)info->dlpi_phdr,
                          (int)info->dlpi_phnum);
            return 0;
        },
        nullptr, XDL_DEFAULT);
    xdl_close(handle);
}

void parseInfo(void *handle) {
    xdl_info_t info;
    xdl_info(handle, XDL_DI_DLINFO, &info);
    xdl_close(handle);
    console->info("\n{}", XdlInfoToString(&info));
}

// private
const char *XdlInfoToString(xdl_info_t *info) {
    type t = type::get<xdl_info_t>();
    std::stringstream os;
    for (auto &prop : t.get_properties()) {
        auto name = prop.get_name();
        rttr::variant value = prop.get_value(info);
        if (value.get_type() == rttr::type::get<const char *>()) {
            const char *cstr = value.get_value<const char *>();
            os << '\t' << name << ": " << (cstr ? cstr : "<null>") << std::endl;
        } else if (value.get_type() == rttr::type::get<size_t>()) {
            os << '\t' << name << ": " << value.get_value<size_t>() << std::endl;
        } else if (value.get_type() == rttr::type::get<void *>()) {
            os << '\t' << name << ": " << value.get_value<void *>() << std::endl;
        } else {
            os << '\t' << name << ": " << value.get_value<void *>() << std::endl;
        }
    }
    return os.str().c_str();
}

void xdl_showAddress___(void *address) {
    xdl_info_t info;
    void *cache;
    if (!xdl_addr(reinterpret_cast<void *>(address), &info, &cache)) {
        console->info("xdl_addr failed");
        return;
    }
    uintptr_t off = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(info.dli_fbase);
    console->info(
        "\t{} | {} [ {:p} ]",
        // "\n\t{} {}",
        info.dli_sname, address, off
        // info.dli_fbase, info.dli_fname
    );
}

void xdl_showAddress(void *address) {
    Dl_info info;
    if (dladdr(address, &info)) {
        console->warn("\t-> {} {} {} {}", info.dli_fbase, info.dli_fname, info.dli_saddr, info.dli_sname);
    }
}

void xdl_showAddress(PTR address) {
    xdl_showAddress(reinterpret_cast<void *>(address));
}

BINDFUNC(xdl) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("xdl")
        .addFunction("info",
                     luabridge::overload<>(info_self),
                     luabridge::overload<PTR>(info),
                     luabridge::overload<const char *>(info))
        .addFunction("iteratePhdr", iteratePhdr)
        .addFunction("addressInfo", addressInfo)
        .addFunction("xdl_open",
                     luabridge::overload<const char *>(_xdl_open),
                     luabridge::overload<const char *, int>(_xdl_open))
        .addFunction("xdl_close", _xdl_close)
        .addFunction("xdl_showAddress",
                     luabridge::overload<void *>(xdl_showAddress),
                     luabridge::overload<PTR>(xdl_showAddress))
        .addFunction("xdl_sym",
                     luabridge::overload<PTR, const char *>(_xdl_sym),
                     luabridge::overload<PTR, const char *, ElfW(Sym) *>(_xdl_sym))
        .addFunction("xdl_dsym",
                     luabridge::overload<PTR, const char *>(_xdl_dsym),
                     luabridge::overload<PTR, const char *, PTR>(_xdl_dsym))
        .endNamespace();
}