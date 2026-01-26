#include "art/dex_instruction.h"
#include "log.h"
#include "xdl.h"
#include <cstring>

namespace art {

// 缓存的指令描述符数组指针
static const InstructionDescriptor* g_instruction_descriptors = nullptr;

// 缓存的指令名称数组指针
static const char* const* g_instruction_names = nullptr;

// 获取指令描述符数组
// art::Instruction::kInstructionDescriptors
// _ZN3art11Instruction23kInstructionDescriptorsE
const InstructionDescriptor* Instruction::GetInstructionDescriptors() {
    if (g_instruction_descriptors != nullptr) {
        return g_instruction_descriptors;
    }
    
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return nullptr;
    }
    
    g_instruction_descriptors = static_cast<const InstructionDescriptor*>(
        xdl_sym(handle, "_ZN3art11Instruction23kInstructionDescriptorsE", nullptr));
    
    xdl_close(handle);
    return g_instruction_descriptors;
}

// 获取指令名称数组
// art::Instruction::kInstructionNames
// _ZN3art11Instruction17kInstructionNamesE
const char* const* Instruction::GetInstructionNames() {
    if (g_instruction_names != nullptr) {
        return g_instruction_names;
    }
    
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return nullptr;
    }
    
    g_instruction_names = static_cast<const char* const*>(
        xdl_sym(handle, "_ZN3art11Instruction17kInstructionNamesE", nullptr));
    
    xdl_close(handle);
    return g_instruction_names;
}

// 获取指令名称
const char* Instruction::GetOpcodeName() const {
    const char* const* names = GetInstructionNames();
    if (names == nullptr) {
        return "unknown";
    }
    
    uint8_t opcode = Opcode();
    if (opcode > 0xFF) {
        return "invalid";
    }
    
    return names[opcode];
}

// 获取复杂操作码的大小
// art::Instruction::SizeInCodeUnitsComplexOpcode() const
// _ZNK3art11Instruction28SizeInCodeUnitsComplexOpcodeEv
size_t Instruction::SizeInCodeUnitsComplexOpcode() const {
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        // 回退：手动处理
        uint16_t ident = insns_[0];
        if (ident == 0x0100) {  // packed-switch-payload
            return 4 + insns_[1] * 2;
        } else if (ident == 0x0200) {  // sparse-switch-payload
            return 2 + insns_[1] * 4;
        } else if (ident == 0x0300) {  // fill-array-data-payload
            uint16_t element_width = insns_[1];
            uint32_t size = insns_[2] | (static_cast<uint32_t>(insns_[3]) << 16);
            return (4 + (element_width * size + 1) / 2);
        }
        return 1;
    }
    
    typedef size_t (*SizeInCodeUnitsComplexOpcodeFunc)(const Instruction*);
    auto func = reinterpret_cast<SizeInCodeUnitsComplexOpcodeFunc>(
        xdl_sym(handle, "_ZNK3art11Instruction28SizeInCodeUnitsComplexOpcodeEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        // 回退
        uint16_t ident = insns_[0];
        if (ident == 0x0100) {
            return 4 + insns_[1] * 2;
        } else if (ident == 0x0200) {
            return 2 + insns_[1] * 4;
        } else if (ident == 0x0300) {
            uint16_t element_width = insns_[1];
            uint32_t size = insns_[2] | (static_cast<uint32_t>(insns_[3]) << 16);
            return (4 + (element_width * size + 1) / 2);
        }
        return 1;
    }
    
    size_t result = func(this);
    xdl_close(handle);
    
    return result;
}

size_t Instruction::SizeInCodeUnits() const {
    uint8_t opcode = Opcode();
    
    // 尝试从 InstructionDescriptor 获取大小
    const InstructionDescriptor* descriptors = GetInstructionDescriptors();
    if (descriptors != nullptr) {
        int8_t size = descriptors[opcode].size_in_code_units;
        if (size < 0) {
            // 可变长度指令，需要调用 SizeInCodeUnitsComplexOpcode
            return SizeInCodeUnitsComplexOpcode();
        }
        return static_cast<size_t>(size);
    }
    
    // 回退：使用静态表
    // 指令大小表（以 code units 为单位）
    // 参考 art/libdexfile/dex/dex_instruction.cc
    static const uint8_t kInstructionSizeInCodeUnits[] = {
        1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,  // 0x00 - 0x0f
        1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,  // 0x10 - 0x1f
        2, 1, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x20 - 0x2f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x30 - 0x3f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x40 - 0x4f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x50 - 0x5f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x60 - 0x6f
        2, 2, 2, 2, 3, 3, 3, 3, 3, 0, 3, 3, 3, 3, 3, 0,  // 0x70 - 0x7f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x80 - 0x8f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0x90 - 0x9f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xa0 - 0xaf
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xb0 - 0xbf
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xc0 - 0xcf
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 0xd0 - 0xdf
        2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xe0 - 0xef
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xf0 - 0xff
    };
    
    // 特殊处理可变长度指令
    if (opcode == 0x00) {  // nop
        // nop 可能是 payload 的一部分，需要检查
        uint16_t ident = insns_[0];
        if (ident == 0x0100) {  // packed-switch-payload
            return 4 + insns_[1] * 2;
        } else if (ident == 0x0200) {  // sparse-switch-payload
            return 2 + insns_[1] * 4;
        } else if (ident == 0x0300) {  // fill-array-data-payload
            uint16_t element_width = insns_[1];
            uint32_t size = insns_[2] | (static_cast<uint32_t>(insns_[3]) << 16);
            return (4 + (element_width * size + 1) / 2);
        }
    }
    
    return kInstructionSizeInCodeUnits[opcode];
}

std::string Instruction::DumpHexLE(size_t instr_code_units) const {
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        // 回退：手动格式化
        size_t size = SizeInCodeUnits();
        if (size > instr_code_units) {
            size = instr_code_units;
        }
        
        std::string result;
        for (size_t i = 0; i < size; i++) {
            char buf[8];
            snprintf(buf, sizeof(buf), "%04x ", insns_[i]);
            result += buf;
        }
        return result;
    }
    
    // art::Instruction::DumpHexLE(size_t) const
    // 返回 std::string，使用 RVO (Return Value Optimization)
    typedef void (*DumpHexLEFunc)(std::string*, const Instruction*, size_t);
    auto func = reinterpret_cast<DumpHexLEFunc>(
        xdl_sym(handle, "_ZNK3art11Instruction9DumpHexLEEm", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        // 回退
        size_t size = SizeInCodeUnits();
        std::string result;
        for (size_t i = 0; i < size && i < instr_code_units; i++) {
            char buf[8];
            snprintf(buf, sizeof(buf), "%04x ", insns_[i]);
            result += buf;
        }
        return result;
    }
    
    std::string result;
    size_t real_size = SizeInCodeUnits();
    size_t dump_size = (real_size > instr_code_units) ? real_size : instr_code_units;
    
    func(&result, this, dump_size);
    xdl_close(handle);
    
    return result;
}

std::string Instruction::DumpString(const DexFile* dex_file) const {
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return "(libdexfile.so not found)";
    }
    
    // art::Instruction::DumpString(art::DexFile const*) const
    typedef void (*DumpStringFunc)(std::string*, const Instruction*, const DexFile*);
    auto func = reinterpret_cast<DumpStringFunc>(
        xdl_sym(handle, "_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return "(DumpString symbol not found)";
    }
    
    std::string result;
    func(&result, this, dex_file);
    xdl_close(handle);
    
    return result;
}

} // namespace art
