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
    
    // 从 ART 的 kInstructionDescriptors 获取指令大小
    const InstructionDescriptor* descriptors = GetInstructionDescriptors();
    if (descriptors != nullptr) {
        int8_t size = descriptors[opcode].size_in_code_units;
        if (size < 0) {
            // 可变长度指令（payload），调用 SizeInCodeUnitsComplexOpcode
            return SizeInCodeUnitsComplexOpcode();
        }
        return static_cast<size_t>(size);
    }
    
    // 回退：手动处理可变长度指令（payload）
    // 当 libdexfile.so 符号不可用时
    if (opcode == 0x00) {
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
    
    // 回退：返回默认大小 1（最小指令大小）
    // 注意：这只在 kInstructionDescriptors 符号不可用时使用
    // 正常情况下应该总是能获取到 ART 的描述符
    return 1;
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
    // ARM64 调用约定：直接返回 std::string
    typedef std::string (*DumpHexLEFunc)(const uint16_t*, size_t);
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
    
    size_t real_size = SizeInCodeUnits();
    size_t dump_size = (real_size > instr_code_units) ? real_size : instr_code_units;
    
    std::string result = func(insns_, dump_size);
    xdl_close(handle);
    
    return result;
}

std::string Instruction::DumpString(const DexFile* dex_file) const {
    void* handle = xdl_open("libdexfile.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return "(libdexfile.so not found)";
    }
    
    // art::Instruction::DumpString(art::DexFile const*) const
    // ARM64 调用约定：返回 std::string
    // 参数：this (insns_), dex_file
    // 返回：std::string (直接返回)
    typedef std::string (*DumpStringFunc)(const uint16_t*, const DexFile*);
    auto func = reinterpret_cast<DumpStringFunc>(
        xdl_sym(handle, "_ZNK3art11Instruction10DumpStringEPKNS_7DexFileE", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return "(DumpString symbol not found)";
    }
    
    std::string result = func(insns_, dex_file);
    xdl_close(handle);
    
    return result;
}

} // namespace art
