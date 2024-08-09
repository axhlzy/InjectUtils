//
// Created by pc on 2023/8/7.
//

#include "InsCheck.h"

constexpr uint32_t Thumb16Mask = 0b11111 << 11;
constexpr uint32_t Thumb16Value = 0b11100 << 11;
constexpr uint32_t Thumb16BLMask = 0b11111 << 11;
constexpr uint32_t Thumb16BLValue = 0b11110 << 11;

constexpr uint32_t Thumb32Mask = 0b11111 << 27;
constexpr uint32_t Thumb32Value = 0b11110 << 27;

constexpr uint32_t Thumb32BLXMask = 0b1111111111 << 22;
constexpr uint32_t Thumb32BLXValue = 0b1111011111 << 22;

constexpr uint32_t Thumb16BRMask = 0b111111 << 10;
constexpr uint32_t Thumb16BRValue = 0b010001 << 10;

constexpr uint64_t Arm64Mask = 0b111111 << 26;
constexpr uint64_t Arm64Value = 0b100101 << 26;
constexpr uint64_t Arm64BLMask = 0b111111 << 26;
constexpr uint64_t Arm64BLValue = 0b100101 << 26;
constexpr uint64_t Arm64BRMask = 0b11111111111 << 21;
constexpr uint64_t Arm64BRValue = 0b11010110000 << 21;

#define ENABLE_INS_CHECK false

bool InsCheck::check(void *ins_ptr) {

#if ENABLE_INS_CHECK

#ifdef __aarch64__
    uint64_t instruction64 = *(static_cast<uint64_t*>(ins_ptr));
    if ((instruction64 & Arm64Mask) == Arm64Value) {
        return true;
    }
    if ((instruction64 & Arm64BLMask) == Arm64BLValue) {
        return true;
    }
    if ((instruction64 & Arm64BRMask) == Arm64BRValue) {
        return true;
    }
#endif

#ifdef __arm__
    uint32_t instruction32 = *(static_cast<uint32_t*>(ins_ptr));
    uint16_t instruction16 = *(static_cast<uint16_t*>(ins_ptr));

    if ((instruction32 & Thumb32Mask) == Thumb32Value) {
        return true;
    }
    if ((instruction16 & Thumb16Mask) == Thumb16Value) {
        return true;
    }
    if ((instruction32 & Thumb32BLXMask) == Thumb32BLXValue) {
        return true;
    }
    if ((instruction16 & Thumb16BLMask) == Thumb16BLValue) {
        return true;
    }
    if ((instruction16 & Thumb16BRMask) == Thumb16BRValue) {
        return true;
    }
#endif

    return false;
#else
    return false;
#endif
}
