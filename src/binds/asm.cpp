#include "bindings.h"

#include "capstone/capstone.h"
#include "keystone/keystone.h"

#if defined(__ARM64__) || defined(__aarch64__)
auto KS_CURRENT_ARCH = ks_arch::KS_ARCH_ARM64;
auto CS_CURRENT_ARCH = cs_arch::CS_ARCH_AARCH64;
auto KS_CURRENT_MODE = ks_mode::KS_MODE_LITTLE_ENDIAN;
auto CS_CURRENT_MODE = cs_mode::CS_MODE_ARM;
#elif defined(__ARM__)
auto KS_CURRENT_ARCH = ks_arch::KS_ARCH_ARM;
auto CS_CURRENT_ARCH = cs_arch::CS_ARCH_ARM;
auto KS_CURRENT_MODE = ks_mode::KS_MODE_LITTLE_ENDIAN;
auto CS_CURRENT_MODE = cs_mode::CS_MODE_ARM;
// #elif defined(__x86_64__) || defined(_M_X64)
// auto KS_CURRENT_ARCH = KS_ARCH_X86;
// auto CS_CURRENT_ARCH = CS_ARCH_X86;
// auto KS_CURRENT_MODE = KS_MODE_LITTLE_ENDIAN;
// auto CS_CURRENT_MODE = CS_MODE_64;
// #elif defined(__i386__) || defined(_M_IX86)
// auto KS_CURRENT_ARCH = KS_ARCH_X86;
// auto CS_CURRENT_ARCH = CS_ARCH_X86;
// auto CS_CURRENT_MODE = KS_MODE_LITTLE_ENDIAN;
// auto CS_CURRENT_MODE = CS_MODE_32;
#else
#error "Unsupported architecture!"
#endif

void keystone_bind(const char *assembly_code, const char *arch) {
    ks_engine *ks;
    ks_err err;
    unsigned char *encode;
    size_t encode_size;
    size_t count;

    if (strlen(arch) != 0) {
        if (strcmp(arch, "arm64") == 0) {
            KS_CURRENT_ARCH = ks_arch::KS_ARCH_ARM64;
        } else if (strcmp(arch, "arm") == 0) {
            KS_CURRENT_ARCH = ks_arch::KS_ARCH_ARM;
        }
        // else if (strcmp(arch, "x86") == 0) {
        //     KS_CURRENT_ARCH = ks_arch::KS_ARCH_X86;
        // } else if (strcmp(arch, "x64") == 0) {
        //     KS_CURRENT_ARCH = ks_arch::KS_ARCH_X86;
        // }
    }
    err = ks_open(KS_CURRENT_ARCH, KS_CURRENT_MODE, &ks);
    if (err != KS_ERR_OK) {
        console->info("ERROR: failed to initialize keystone engine! error code: {}", err);
        return;
    }

    if (ks_asm(ks, assembly_code, 0, &encode, &encode_size, &count) != KS_ERR_OK) {
        console->info("ERROR: failed to assemble code!");
    } else {
        console->info("Assembled: {}, bytes: ", assembly_code);
        for (size_t i = 0; i < encode_size; i++) {
            console->info("{:02x} ", (unsigned int)encode[i]);
        }
        console->info("");
        ks_free(encode);
    }

    ks_close(ks);
}

void keystone_bind(const char *assembly_code) {
    keystone_bind(assembly_code, "");
}

void capstone_bind(PTR arm64_code, size_t size) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_CURRENT_ARCH, CS_CURRENT_MODE, &handle) != CS_ERR_OK) {
        console->info("ERROR: Failed to initialize Capstone engine!");
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, (const uint8_t *)arm64_code, size * 4, (uint64_t)arm64_code, 0, &insn);
    std::string info;
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            info += fmt::format("\t{}0x{:x}: {} {}\n", j == 0 ? "-> " : "   ",
                                insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        console->info("Disassembled:\n{}", info);
        cs_free(insn, count);
    } else {
        console->info("ERROR: Failed to disassemble code!");
    }
}

void capstone_bind(PTR arm64_code) {
    capstone_bind(arm64_code, 10);
}

BINDFUNC(asm) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("asm")
        .addFunction("ks",
                     luabridge::overload<const char *>(&keystone_bind),
                     luabridge::overload<const char *, const char *>(&keystone_bind))
        .addFunction("cs",
                     luabridge::overload<PTR>(&capstone_bind),
                     luabridge::overload<PTR, size_t>(&capstone_bind))
        .endNamespace();

    // alias
    luabridge::getGlobalNamespace(L)
        .addFunction("ks",
                     luabridge::overload<const char *>(&keystone_bind),
                     luabridge::overload<const char *, const char *>(&keystone_bind))
        .addFunction("cs",
                     luabridge::overload<PTR>(&capstone_bind),
                     luabridge::overload<PTR, size_t>(&capstone_bind))
        .addFunction("dis",
                     luabridge::overload<PTR>(&capstone_bind),
                     luabridge::overload<PTR, size_t>(&capstone_bind));
}
