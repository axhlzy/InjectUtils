//
// Created by pc on 2023/8/7.
//

#include "InsCheck.h"
#include <cstdint>

// ARM64 指令掩码和值
namespace Arm64 {
    constexpr uint32_t BranchMask = 0b111111 << 26;
    constexpr uint32_t BranchValue = 0b100101 << 26;
    constexpr uint32_t BranchLinkMask = 0b111111 << 26;
    constexpr uint32_t BranchLinkValue = 0b100101 << 26;
    constexpr uint32_t BranchRegMask = 0b11111111111 << 21;
    constexpr uint32_t BranchRegValue = 0b11010110000 << 21;
}

// Thumb 指令掩码和值
namespace Thumb {
    constexpr uint16_t Branch16Mask = 0b11111 << 11;
    constexpr uint16_t Branch16Value = 0b11100 << 11;
    constexpr uint16_t BranchLink16Mask = 0b11111 << 11;
    constexpr uint16_t BranchLink16Value = 0b11110 << 11;
    constexpr uint16_t BranchReg16Mask = 0b111111 << 10;
    constexpr uint16_t BranchReg16Value = 0b010001 << 10;
    
    constexpr uint32_t Branch32Mask = 0b11111 << 27;
    constexpr uint32_t Branch32Value = 0b11110 << 27;
    constexpr uint32_t BranchLinkX32Mask = 0b1111111111 << 22;
    constexpr uint32_t BranchLinkX32Value = 0b1111011111 << 22;
}

#define ENABLE_INS_CHECK false

bool InsCheck::check(void *ins_ptr) {
#if ENABLE_INS_CHECK
    if (ins_ptr == nullptr) {
        return false;
    }

#ifdef __aarch64__
    const uint32_t instruction = *static_cast<const uint32_t*>(ins_ptr);
    
    // 检查 ARM64 分支指令
    if ((instruction & Arm64::BranchMask) == Arm64::BranchValue) {
        return true;
    }
    if ((instruction & Arm64::BranchLinkMask) == Arm64::BranchLinkValue) {
        return true;
    }
    if ((instruction & Arm64::BranchRegMask) == Arm64::BranchRegValue) {
        return true;
    }
#endif

#ifdef __arm__
    const uint16_t instruction16 = *static_cast<const uint16_t*>(ins_ptr);
    
    // 检查 Thumb-16 分支指令
    if ((instruction16 & Thumb::Branch16Mask) == Thumb::Branch16Value) {
        return true;
    }
    if ((instruction16 & Thumb::BranchLink16Mask) == Thumb::BranchLink16Value) {
        return true;
    }
    if ((instruction16 & Thumb::BranchReg16Mask) == Thumb::BranchReg16Value) {
        return true;
    }
    
    // 检查 Thumb-32 分支指令
    const uint32_t instruction32 = *static_cast<const uint32_t*>(ins_ptr);
    if ((instruction32 & Thumb::Branch32Mask) == Thumb::Branch32Value) {
        return true;
    }
    if ((instruction32 & Thumb::BranchLinkX32Mask) == Thumb::BranchLinkX32Value) {
        return true;
    }
#endif

    return false;
#else
    (void)ins_ptr; // 避免未使用参数警告
    return false;
#endif
}
