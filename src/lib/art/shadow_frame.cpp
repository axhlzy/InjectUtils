#include "art/shadow_frame.h"
#include "log.h"
#include "xdl.h"

namespace art {

// ========== 字段地址获取 ==========

ShadowFrame** ShadowFrame::GetLinkPtr() {
    return reinterpret_cast<ShadowFrame**>(GetFieldAddress(0));
}

ArtMethod** ShadowFrame::GetMethodPtr() {
    return reinterpret_cast<ArtMethod**>(GetFieldAddress(PointerSize));
}

void** ShadowFrame::GetResultRegisterPtr() {
    return reinterpret_cast<void**>(GetFieldAddress(PointerSize * 2));
}

uint16_t** ShadowFrame::GetDexPcPtrPtr() {
    return reinterpret_cast<uint16_t**>(GetFieldAddress(PointerSize * 3));
}

uint16_t** ShadowFrame::GetDexInstructionsPtr() {
    return reinterpret_cast<uint16_t**>(GetFieldAddress(PointerSize * 4));
}

void** ShadowFrame::GetLockCountDataPtr() {
    return reinterpret_cast<void**>(GetFieldAddress(PointerSize * 5));
}

uint32_t* ShadowFrame::GetNumberOfVRegsPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(PointerSize * 6));
}

uint32_t* ShadowFrame::GetDexPcPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(PointerSize * 6 + 4));
}

int16_t* ShadowFrame::GetCachedHotnessCountdownPtr() {
    return reinterpret_cast<int16_t*>(GetFieldAddress(PointerSize * 6 + 8));
}

int16_t* ShadowFrame::GetHotnessCountdownPtr() {
    return reinterpret_cast<int16_t*>(GetFieldAddress(PointerSize * 6 + 10));
}

uint32_t* ShadowFrame::GetFrameFlagsPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(PointerSize * 6 + 12));
}

uint32_t* ShadowFrame::GetVRegsPtr() {
    return reinterpret_cast<uint32_t*>(GetFieldAddress(PointerSize * 6 + 16));
}

// ========== Getter 方法 ==========

ShadowFrame* ShadowFrame::GetLink() {
    return *GetLinkPtr();
}

ArtMethod* ShadowFrame::GetMethod() {
    return *GetMethodPtr();
}

void* ShadowFrame::GetResultRegister() {
    return *GetResultRegisterPtr();
}

uint16_t* ShadowFrame::GetDexPcPtrValue() {
    return *GetDexPcPtrPtr();
}

uint16_t* ShadowFrame::GetDexInstructions() {
    return *GetDexInstructionsPtr();
}

void* ShadowFrame::GetLockCountData() {
    return *GetLockCountDataPtr();
}

uint32_t ShadowFrame::NumberOfVRegs() {
    return *GetNumberOfVRegsPtr();
}

uint32_t ShadowFrame::GetDexPc() {
    return *GetDexPcPtr();
}

int16_t ShadowFrame::GetCachedHotnessCountdown() {
    return *GetCachedHotnessCountdownPtr();
}

int16_t ShadowFrame::GetHotnessCountdown() {
    return *GetHotnessCountdownPtr();
}

uint32_t ShadowFrame::GetFrameFlags() {
    return *GetFrameFlagsPtr();
}

// ========== Setter 方法 ==========

void ShadowFrame::SetDexPc(uint32_t dex_pc) {
    *GetDexPcPtr() = dex_pc;
}

void ShadowFrame::SetDexPcPtr(uint16_t* dex_pc_ptr) {
    *GetDexPcPtrPtr() = dex_pc_ptr;
}

void ShadowFrame::SetCachedHotnessCountdown(int16_t countdown) {
    *GetCachedHotnessCountdownPtr() = countdown;
}

void ShadowFrame::SetHotnessCountdown(int16_t countdown) {
    *GetHotnessCountdownPtr() = countdown;
}

// ========== VReg 操作方法 ==========

uint32_t ShadowFrame::GetVReg(size_t i) {
    if (i >= NumberOfVRegs()) {
        return 0;
    }
    return GetVRegsPtr()[i];
}

void ShadowFrame::SetVReg(size_t i, uint32_t value) {
    if (i >= NumberOfVRegs()) {
        return;
    }
    GetVRegsPtr()[i] = value;
}

int64_t ShadowFrame::GetVRegLong(size_t i) {
    if (i + 1 >= NumberOfVRegs()) {
        return 0;
    }
    uint32_t* vregs = GetVRegsPtr();
    return *reinterpret_cast<int64_t*>(&vregs[i]);
}

void ShadowFrame::SetVRegLong(size_t i, int64_t value) {
    if (i + 1 >= NumberOfVRegs()) {
        return;
    }
    uint32_t* vregs = GetVRegsPtr();
    *reinterpret_cast<int64_t*>(&vregs[i]) = value;
}

float ShadowFrame::GetVRegFloat(size_t i) {
    if (i >= NumberOfVRegs()) {
        return 0.0f;
    }
    uint32_t* vregs = GetVRegsPtr();
    return *reinterpret_cast<float*>(&vregs[i]);
}

void ShadowFrame::SetVRegFloat(size_t i, float value) {
    if (i >= NumberOfVRegs()) {
        return;
    }
    uint32_t* vregs = GetVRegsPtr();
    *reinterpret_cast<float*>(&vregs[i]) = value;
}

double ShadowFrame::GetVRegDouble(size_t i) {
    if (i + 1 >= NumberOfVRegs()) {
        return 0.0;
    }
    uint32_t* vregs = GetVRegsPtr();
    return *reinterpret_cast<double*>(&vregs[i]);
}

void ShadowFrame::SetVRegDouble(size_t i, double value) {
    if (i + 1 >= NumberOfVRegs()) {
        return;
    }
    uint32_t* vregs = GetVRegsPtr();
    *reinterpret_cast<double*>(&vregs[i]) = value;
}

void* ShadowFrame::GetVRegReference(size_t i) {
    if (i >= NumberOfVRegs()) {
        return nullptr;
    }
    uint32_t num_vregs = NumberOfVRegs();
    // 引用部分在 vregs 数组后半部分，每个引用占用 PointerSize 字节
    uintptr_t ref_base = reinterpret_cast<uintptr_t>(GetVRegsPtr()) + num_vregs * 4;
    return *reinterpret_cast<void**>(ref_base + i * PointerSize);
}

void ShadowFrame::SetVRegReference(size_t i, void* ref) {
    if (i >= NumberOfVRegs()) {
        return;
    }
    uint32_t num_vregs = NumberOfVRegs();
    uintptr_t ref_base = reinterpret_cast<uintptr_t>(GetVRegsPtr()) + num_vregs * 4;
    *reinterpret_cast<void**>(ref_base + i * PointerSize) = ref;
}

// ========== 实用方法 ==========

uint32_t ShadowFrame::GetCurrentDexPC() {
    uint16_t* dex_pc_ptr = GetDexPcPtrValue();
    if (dex_pc_ptr == nullptr) {
        return GetDexPc();
    }
    uint16_t* dex_instructions = GetDexInstructions();
    if (dex_instructions == nullptr) {
        return GetDexPc();
    }
    return static_cast<uint32_t>(dex_pc_ptr - dex_instructions);
}

void* ShadowFrame::GetThisObject(uint16_t num_ins) {
    if (num_ins == 0) {
        // 尝试从方法信息获取参数数量
        // 这里简化处理，假设 this 在最后一个寄存器
        uint32_t num_vregs = NumberOfVRegs();
        if (num_vregs > 0) {
            return GetVRegReference(num_vregs - 1);
        }
        return nullptr;
    }
    // this 对象通常在参数寄存器的第一个位置
    uint32_t num_vregs = NumberOfVRegs();
    if (num_vregs >= num_ins && num_ins > 0) {
        return GetVRegReference(num_vregs - num_ins);
    }
    return nullptr;
}

// ========== 调试方法 ==========

void ShadowFrame::Print() {
    loge("[*] ShadowFrame @ %p", this);
    logi("[*]   link: %p", GetLink());
    logd("[*]   method: %p", GetMethod());
    logd("[*]   result_register: %p", GetResultRegister());
    logd("[*]   dex_pc_ptr: %p", GetDexPcPtrValue());
    logd("[*]   dex_instructions: %p", GetDexInstructions());
    logd("[*]   number_of_vregs: %u", NumberOfVRegs());
    logd("[*]   dex_pc: %u (current: %u)", GetDexPc(), GetCurrentDexPC());
    logd("[*]   cached_hotness_countdown: %d", GetCachedHotnessCountdown());
    logd("[*]   hotness_countdown: %d", GetHotnessCountdown());
    logd("[*]   frame_flags: 0x%x", GetFrameFlags());
}

void ShadowFrame::PrintVRegs(int indent) {
    uint32_t num_vregs = NumberOfVRegs();
    std::string indent_str(indent, ' ');
    loge("%s[*] VRegs (%u total):", indent_str.c_str(), num_vregs);
    for (uint32_t i = 0; i < num_vregs; i++) {
        uint32_t value = GetVReg(i);
        void* ref = GetVRegReference(i);
        if (ref != nullptr) {
            logd("%s[*]   v%u = 0x%08x (%d) [ref: %p]", indent_str.c_str(), i, value, static_cast<int32_t>(value), ref);
        } else {
            logd("%s[*]   v%u = 0x%08x (%d)", indent_str.c_str(), i, value, static_cast<int32_t>(value));
        }
    }
}

void ShadowFrame::PrintBacktrace(const int max_frames) {
    loge("[*] ShadowFrame Backtrace:");
    auto frame = this;
    int frame_index = 0;

    while (frame != nullptr && frame_index < max_frames) {

        logd("[*]   Frame #%d: %p", frame_index, frame);
        logd("[*]     dex_pc: %u, vregs: %u", frame->GetCurrentDexPC(), frame->NumberOfVRegs());
        frame->PrintVRegs(8);

        const ArtMethod *method = frame->GetMethod();
        if (method != nullptr) method->Print();

        frame = frame->GetLink();
        frame_index++;
    }

    if (frame_index >= max_frames && max_frames != 2) {
        logd("[*]   (reached max frames limit) | %d", max_frames);
    }
    loge("[*] Total frames: %d", frame_index);
}

// mirror::Object* GetThisObject(uint16_t num_ins)
// _ZNK3art11ShadowFrame13GetThisObjectEt
void* ShadowFrame::GetThisObjectNative(uint16_t num_ins) const {
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        return const_cast<ShadowFrame*>(this)->GetThisObject(num_ins);
    }
    
    typedef void* (*GetThisObjectFunc)(const ShadowFrame*, uint16_t);
    auto func = reinterpret_cast<GetThisObjectFunc>(
        xdl_sym(handle, "_ZNK3art11ShadowFrame13GetThisObjectEt", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        return const_cast<ShadowFrame*>(this)->GetThisObject(num_ins);
    }
    
    void* result = func(this, num_ins);
    xdl_close(handle);
    
    return result;
}

} // namespace art

void art::ShadowFrame::PrintCurrentInstruction() {
    uint16_t* dex_instructions = GetDexInstructions();
    uint32_t dex_pc = GetCurrentDexPC();
    
    if (dex_instructions == nullptr) {
        loge("[*] Current Instruction: (dex_instructions is null)");
        return;
    }
    
    // 获取当前指令
    const uint16_t* current_insn = dex_instructions + dex_pc;
    Instruction inst(current_insn);
    
    // 获取 DexFile 指针（从 ArtMethod）
    ArtMethod* method = GetMethod();
    const DexFile* dex_file = nullptr;
    if (method != nullptr) {
        dex_file = method->GetDexFile();
    }
    
    loge("[*] Current Instruction at dex_pc 0x%04x:", dex_pc);
    loge("[*]   Opcode: 0x%02x (%s)", inst.Opcode(), inst.GetOpcodeName());
    loge("[*]   Size: %zu code units", inst.SizeInCodeUnits());
    loge("[*]   Hex: %s", inst.DumpHexLE().c_str());
    
    if (dex_file != nullptr) {
        loge("[*]   Smali: %s", inst.DumpString(dex_file).c_str());
    } else {
        loge("[*]   Smali: (DexFile not available)");
    }
}
