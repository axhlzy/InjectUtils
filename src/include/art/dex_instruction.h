#ifndef DEX_INSTRUCTION_H
#define DEX_INSTRUCTION_H

#include "art_common.h"
#include <string>
#include <vector>

namespace art {

// 前向声明
class DexFile;

/**
 * InstructionDescriptor - 指令描述符
 * 参考: art/libdexfile/dex/dex_instruction.h
 * 
 * 内存布局:
 * Offset  Size  Field
 * 0x00    0x04  uint32_t verify_flags
 * 0x04    0x01  uint8_t format (Format enum)
 * 0x05    0x01  uint8_t index_type (IndexType enum)
 * 0x06    0x01  uint8_t flags (Flags enum)
 * 0x07    0x01  int8_t size_in_code_units
 */
struct InstructionDescriptor {
    uint32_t verify_flags;
    uint8_t format;
    uint8_t index_type;
    uint8_t flags;
    int8_t size_in_code_units;
} __attribute__((packed));

/**
 * Instruction 类 - DEX 字节码指令
 * 参考: art/libdexfile/dex/dex_instruction.h
 * 
 * 用于解析和显示 DEX 字节码指令
 */
class Instruction {
private:
    const uint16_t* insns_;  // 指向指令的指针
    
    // 获取指令描述符数组（通过 xdl 从 libdexfile.so 加载）
    static const InstructionDescriptor* GetInstructionDescriptors();
    
    // 获取指令名称数组（通过 xdl 从 libdexfile.so 加载）
    static const char* const* GetInstructionNames();
    
public:
    // 构造函数
    explicit Instruction(const uint16_t* insns) : insns_(insns) {}
    
    // 获取指令指针
    const uint16_t* GetInsns() const { return insns_; }
    
    // 读取指令的 uint16_t 值
    uint16_t Fetch16(size_t offset = 0) const {
        return insns_[offset];
    }
    
    // 获取操作码
    uint8_t Opcode() const {
        return static_cast<uint8_t>(insns_[0] & 0xFF);
    }
    
    // 获取指令名称
    const char* GetOpcodeName() const;
    
    // 获取指令的大小（以 code units 为单位，1 code unit = 2 bytes）
    size_t SizeInCodeUnits() const;
    
    // 获取复杂操作码的大小（用于可变长度指令）
    // art::Instruction::SizeInCodeUnitsComplexOpcode() const
    // _ZNK3art11Instruction28SizeInCodeUnitsComplexOpcodeEv
    size_t SizeInCodeUnitsComplexOpcode() const;
    
    // Dump 指令的十六进制表示
    // art::Instruction::DumpHexLE(size_t) const
    // _ZNK3art11Instruction9DumpHexLEEm
    std::string DumpHexLE(size_t instr_code_units = 3) const;
    
    // Dump 指令的字符串表示（Smali 格式）
    // art::Instruction::DumpString(art::DexFile const*) const
    // _ZNK3art11Instruction10DumpStringEPKNS_7DexFileE
    std::string DumpString(const DexFile* dex_file) const;
    
    // 获取下一条指令
    const Instruction* Next() const {
        return reinterpret_cast<const Instruction*>(insns_ + SizeInCodeUnits());
    }
    
    // 获取相对偏移的指令
    const Instruction* RelativeAt(int32_t offset) const {
        return reinterpret_cast<const Instruction*>(insns_ + offset);
    }
};

/**
 * DexFile 类 - DEX 文件的最小表示
 * 仅用于传递给 Instruction::DumpString
 * 
 * 注意：这是一个不完整的类定义，仅包含必要的字段
 * 完整定义在 art/libdexfile/dex/dex_file.h
 */
class DexFile {
    // 这里不需要实现任何内容
    // 只是作为类型占位符，实际使用时传递 ART 运行时的 DexFile 指针
};

} // namespace art

#endif // DEX_INSTRUCTION_H
