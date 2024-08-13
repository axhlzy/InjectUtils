#include "bindings.h"

#include "capstone/capstone.h"
#include "keystone/keystone.h"

ks_arch KS_CURRENT_ARCH = KS_ARCH_ARM64;
ks_mode KS_CURRENT_MODE = KS_MODE_LITTLE_ENDIAN;

cs_arch CS_CURRENT_ARCH = CS_ARCH_ARM64;
cs_mode CS_CURRENT_MODE = CS_MODE_ARM;

void keystone_bind(const char *assembly_code, const char *arch) {
    ks_engine *ks;
    ks_err err;
    unsigned char *encode;
    size_t encode_size;
    size_t count;

    if (arch == "arm64") {
        KS_CURRENT_ARCH = KS_ARCH_ARM64;
    } else if (arch == "arm") {
        KS_CURRENT_ARCH = KS_ARCH_ARM;
    } else if (arch == "x86") {
        KS_CURRENT_ARCH = KS_ARCH_X86;
    } else if (arch == "x64") {
        KS_CURRENT_ARCH = KS_ARCH_X86;
    }

    err = ks_open(KS_CURRENT_ARCH, KS_CURRENT_MODE, &ks);
    if (err != KS_ERR_OK) {
        std::cout << "ERROR: failed to initialize keystone engine! error code: " << err << std::endl;
        return;
    }

    if (ks_asm(ks, assembly_code, 0, &encode, &encode_size, &count) != KS_ERR_OK) {
        std::cout << "ERROR: failed to assemble code!" << std::endl;
    } else {
        std::cout << "Assembled: " << assembly_code << ", bytes: ";
        for (size_t i = 0; i < encode_size; i++) {
            std::cout << std::hex << (unsigned int)encode[i] << " ";
        }
        std::cout << std::endl;
        ks_free(encode);
    }

    ks_close(ks);
}

void keystone_bind(const char *assembly_code) {
    keystone_bind(assembly_code, "arm64");
}

void capstone_bind(PTR arm64_code, size_t size) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_CURRENT_ARCH, CS_CURRENT_MODE, &handle) != CS_ERR_OK) {
        std::cerr << "ERROR: Failed to initialize Capstone engine!" << std::endl;
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, (const uint8_t *)arm64_code, size * 4, (uint64_t)arm64_code, 0, &insn);
    if (count > 0) {
        std::cout << "Disassembly code:" << std::endl;
        for (size_t j = 0; j < count; j++) {
            std::cout << "0x" << std::hex << insn[j].address << ": "
                      << insn[j].mnemonic << " " << insn[j].op_str << std::endl;
        }

        cs_free(insn, count);
    } else {
        std::cerr << "ERROR: Failed to disassemble code!" << std::endl;
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

    // // test
    // keystone_bind("mov x0, x1; b.eq 0x100");
    // capstone_bind((PTR)reg_asm, 20);
}