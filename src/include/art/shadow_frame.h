#ifndef SHADOW_FRAME_H
#define SHADOW_FRAME_H

#include "art_common.h"
#include "art_method.h"
#include "dex_instruction.h"

namespace art {

/**
 * ShadowFrame 类
 * 参考: art/runtime/interpreter/shadow_frame.h
 * 
 * 内存布局:
 * Offset      Size  Field
 * ----------  ----  -----
 * 0x00        PTR   ShadowFrame* link_
 * PTR         PTR   ArtMethod* method_
 * PTR*2       PTR   JValue* result_register_
 * PTR*3       PTR   const uint16_t* dex_pc_ptr_
 * PTR*4       PTR   const uint16_t* dex_instructions_
 * PTR*5       PTR   LockCountData lock_count_data_
 * PTR*6       0x04  uint32_t number_of_vregs_
 * PTR*6+4     0x04  uint32_t dex_pc_
 * PTR*6+8     0x02  int16_t cached_hotness_countdown_
 * PTR*6+10    0x02  int16_t hotness_countdown_
 * PTR*6+12    0x04  uint32_t frame_flags_
 * PTR*6+16    VAR   uint32_t vregs_[number_of_vregs * 2]
 */
class ShadowFrame {
private:
    uintptr_t GetFieldAddress(size_t offset) const {
        return reinterpret_cast<uintptr_t>(this) + offset;
    }
    
public:
    // ========== 字段地址获取 ==========
    ShadowFrame** GetLinkPtr();
    ArtMethod** GetMethodPtr();
    void** GetResultRegisterPtr();
    uint16_t** GetDexPcPtrPtr();
    uint16_t** GetDexInstructionsPtr();
    void** GetLockCountDataPtr();
    uint32_t* GetNumberOfVRegsPtr();
    uint32_t* GetDexPcPtr();
    int16_t* GetCachedHotnessCountdownPtr();
    int16_t* GetHotnessCountdownPtr();
    uint32_t* GetFrameFlagsPtr();
    uint32_t* GetVRegsPtr();
    
    // ========== Getter 方法 ==========
    ShadowFrame* GetLink();
    ArtMethod* GetMethod();
    void* GetResultRegister();
    uint16_t* GetDexPcPtrValue();
    uint16_t* GetDexInstructions();
    void* GetLockCountData();
    uint32_t NumberOfVRegs();
    uint32_t GetDexPc();
    int16_t GetCachedHotnessCountdown();
    int16_t GetHotnessCountdown();
    uint32_t GetFrameFlags();
    
    // ========== Setter 方法 ==========
    void SetDexPc(uint32_t dex_pc);
    void SetDexPcPtr(uint16_t* dex_pc_ptr);
    void SetCachedHotnessCountdown(int16_t countdown);
    void SetHotnessCountdown(int16_t countdown);
    
    // ========== VReg 操作方法 ==========
    
    // 32-bit operations
    uint32_t GetVReg(size_t i);
    void SetVReg(size_t i, uint32_t value);
    
    // 64-bit operations
    int64_t GetVRegLong(size_t i);
    void SetVRegLong(size_t i, int64_t value);
    
    // Float operations
    float GetVRegFloat(size_t i);
    void SetVRegFloat(size_t i, float value);
    
    // Double operations
    double GetVRegDouble(size_t i);
    void SetVRegDouble(size_t i, double value);
    
    // Reference operations
    void* GetVRegReference(size_t i);
    void SetVRegReference(size_t i, void* ref);
    
    // ========== 实用方法 ==========
    uint32_t GetCurrentDexPC();
    void* GetThisObject(uint16_t num_ins = 0);
    
    // ========== 调试方法 ==========
    void Print();
    void PrintVRegs(int indent = 0);
    void PrintBacktrace(int max_frames = 32);
    void PrintCurrentInstruction();  // 打印当前 dex_pc 位置的指令
    
    // ========== ART 符号调用（使用 xdl） ==========
    
    // mirror::Object* GetThisObject(uint16_t num_ins)
    // _ZNK3art11ShadowFrame13GetThisObjectEt
    void* GetThisObjectNative(uint16_t num_ins) const;
};

} // namespace art

#endif // SHADOW_FRAME_H
