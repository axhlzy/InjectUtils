#include "art/shadow_frame.h"
#include "log.h"
#include "xdl.h"
#include <jni.h>

namespace art {

// 获取对象的类型名称（调用 mirror::Object::PrettyTypeOf）
static std::string GetObjectPrettyTypeOf(void* obj) {
    if (obj == nullptr) {
        return "null";
    }
    
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "Object<%p>", obj);
        return buf;
    }
    
    // std::string PrettyTypeOf()
    // _ZN3art6mirror6Object12PrettyTypeOfEv
    typedef std::string (*PrettyTypeOfFunc)(void*);
    auto func = reinterpret_cast<PrettyTypeOfFunc>(
        xdl_sym(handle, "_ZN3art6mirror6Object12PrettyTypeOfEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        char buf[32];
        snprintf(buf, sizeof(buf), "Object<%p>", obj);
        return buf;
    }
    
    std::string result = func(obj);
    xdl_close(handle);
    
    if (result.empty()) {
        char buf[32];
        snprintf(buf, sizeof(buf), "Object<%p>", obj);
        return buf;
    }
    
    // 格式化为 ArtObject<ptr> <- TypeName
    char buf[512];
    snprintf(buf, sizeof(buf), "ArtObject<%p> <- %s", obj, result.c_str());
    return buf;
}

// 获取 java.lang.String 对象的字符串值
// JavaString 内存布局: ArtObject(8) + count_(4) + hash_code_(4) + value_data
static std::string GetJavaStringValue(void* obj, size_t max_len = 64) {
    if (obj == nullptr) {
        return "";
    }
    
    // ArtObject 大小: klass_(4) + monitor_(4) = 8 bytes
    constexpr size_t kArtObjectSize = 8;
    // count_ 在 ArtObject 之后
    uintptr_t obj_addr = reinterpret_cast<uintptr_t>(obj);
    int32_t count = *reinterpret_cast<int32_t*>(obj_addr + kArtObjectSize);
    
    // 字符串数据在 count_(4) + hash_code_(4) 之后
    const char* str_data = reinterpret_cast<const char*>(obj_addr + kArtObjectSize + 8);
    
    if (count <= 0 || count > 10000) {
        return "";
    }
    
    // 限制长度，避免过长
    size_t len = static_cast<size_t>(count);
    if (len > max_len) {
        len = max_len;
    }
    
    std::string result(str_data, len);
    if (static_cast<size_t>(count) > max_len) {
        result += "...";
    }
    return result;
}

// 获取对象的简单展示信息（类似 TypeScript 的 simpleDisp）
// 对于 java.lang.String 类型，会额外显示字符串内容
// 格式: ArtObject<ptr> | jobject<ptr> <- TypeName | toString_result
static std::string GetObjectSimpleDisp(void* obj) {
    if (obj == nullptr) {
        return "null";
    }
    
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        char buf[32];
        snprintf(buf, sizeof(buf), "ArtObject<%p>", obj);
        return buf;
    }
    
    // std::string PrettyTypeOf()
    // _ZN3art6mirror6Object12PrettyTypeOfEv
    typedef std::string (*PrettyTypeOfFunc)(void*);
    auto func = reinterpret_cast<PrettyTypeOfFunc>(
        xdl_sym(handle, "_ZN3art6mirror6Object12PrettyTypeOfEv", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        char buf[32];
        snprintf(buf, sizeof(buf), "ArtObject<%p>", obj);
        return buf;
    }
    
    std::string type_name = func(obj);
    std::string toString_result;
    std::string fields_info;
    jobject jobj_ref = nullptr;  // 保存 jobject 引用用于格式化

    using JNI_GetCreatedJavaVMs_t = jint (*)(JavaVM**, jsize, jsize*);
    auto JNI_GetCreatedJavaVMs = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(
        xdl_sym(handle, "JNI_GetCreatedJavaVMs", nullptr));
    
    if (JNI_GetCreatedJavaVMs != nullptr) {
        JavaVM* vm = nullptr;
        jsize nVMs = 0;
        JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);
        
        if (vm != nullptr) {
            JNIEnv* env = nullptr;
            if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env != nullptr) {
                jobject jobj = art::ArtObjectToJobject(env, obj);
                if (jobj != nullptr) {
                    jobj_ref = jobj;  // 保存引用
                    
                    // 调用 toString() 方法
                    jclass objClass = env->GetObjectClass(jobj);
                    if (objClass != nullptr) {
                        jmethodID toStringMethod = env->GetMethodID(objClass, "toString", "()Ljava/lang/String;");
                        if (toStringMethod != nullptr) {
                            jstring jstr = (jstring)env->CallObjectMethod(jobj, toStringMethod);
                            if (jstr != nullptr && !env->ExceptionCheck()) {
                                const char* str = env->GetStringUTFChars(jstr, nullptr);
                                if (str != nullptr) {
                                    toString_result = str;
                                    env->ReleaseStringUTFChars(jstr, str);
                                }
                                env->DeleteLocalRef(jstr);
                            }
                            if (env->ExceptionCheck()) {
                                env->ExceptionClear();
                            }
                        }
                        
                        // 获取实例成员变量
                        jclass classClass = env->FindClass("java/lang/Class");
                        if (classClass != nullptr) {
                            jmethodID getDeclaredFields = env->GetMethodID(classClass, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
                            if (getDeclaredFields != nullptr) {
                                jobjectArray fields = (jobjectArray)env->CallObjectMethod(objClass, getDeclaredFields);
                                if (fields != nullptr && !env->ExceptionCheck()) {
                                    jsize fieldCount = env->GetArrayLength(fields);
                                    jclass fieldClass = env->FindClass("java/lang/reflect/Field");
                                    jmethodID setAccessible = env->GetMethodID(fieldClass, "setAccessible", "(Z)V");
                                    jmethodID getName = env->GetMethodID(fieldClass, "getName", "()Ljava/lang/String;");
                                    jmethodID get = env->GetMethodID(fieldClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
                                    jmethodID getModifiers = env->GetMethodID(fieldClass, "getModifiers", "()I");
                                    
                                    // java.lang.reflect.Modifier.STATIC = 8
                                    const int MODIFIER_STATIC = 8;
                                    
                                    for (jsize i = 0; i < fieldCount && i < 10; i++) {  // 限制最多10个字段
                                        jobject field = env->GetObjectArrayElement(fields, i);
                                        if (field == nullptr) continue;
                                        
                                        // 检查是否是静态字段，跳过静态字段
                                        jint modifiers = env->CallIntMethod(field, getModifiers);
                                        if (modifiers & MODIFIER_STATIC) {
                                            env->DeleteLocalRef(field);
                                            continue;
                                        }
                                        
                                        // 设置可访问
                                        env->CallVoidMethod(field, setAccessible, JNI_TRUE);
                                        if (env->ExceptionCheck()) {
                                            env->ExceptionClear();
                                            env->DeleteLocalRef(field);
                                            continue;
                                        }
                                        
                                        // 获取字段名
                                        jstring fieldName = (jstring)env->CallObjectMethod(field, getName);
                                        const char* nameStr = fieldName ? env->GetStringUTFChars(fieldName, nullptr) : nullptr;
                                        
                                        // 获取字段值
                                        jobject fieldValue = env->CallObjectMethod(field, get, jobj);
                                        if (env->ExceptionCheck()) {
                                            env->ExceptionClear();
                                            if (nameStr) {
                                                fields_info += "\n      " + std::string(nameStr) + " = <access error>";
                                                env->ReleaseStringUTFChars(fieldName, nameStr);
                                            }
                                            if (fieldName) env->DeleteLocalRef(fieldName);
                                            env->DeleteLocalRef(field);
                                            continue;
                                        }
                                        
                                        std::string valueStr;
                                        if (fieldValue == nullptr) {
                                            valueStr = "null";
                                        } else {
                                            // 调用字段值的 toString
                                            jclass valueClass = env->GetObjectClass(fieldValue);
                                            jmethodID valueToString = env->GetMethodID(valueClass, "toString", "()Ljava/lang/String;");
                                            if (valueToString != nullptr) {
                                                jstring valueJStr = (jstring)env->CallObjectMethod(fieldValue, valueToString);
                                                if (valueJStr != nullptr && !env->ExceptionCheck()) {
                                                    const char* valStr = env->GetStringUTFChars(valueJStr, nullptr);
                                                    if (valStr != nullptr) {
                                                        valueStr = valStr;
                                                        // 截断过长的值
                                                        if (valueStr.length() > 50) {
                                                            valueStr = valueStr.substr(0, 50) + "...";
                                                        }
                                                        env->ReleaseStringUTFChars(valueJStr, valStr);
                                                    }
                                                    env->DeleteLocalRef(valueJStr);
                                                }
                                            }
                                            if (env->ExceptionCheck()) {
                                                env->ExceptionClear();
                                                valueStr = "<toString error>";
                                            }
                                            env->DeleteLocalRef(valueClass);
                                            env->DeleteLocalRef(fieldValue);
                                        }
                                        
                                        if (nameStr != nullptr) {
                                            fields_info += "\n      " + std::string(nameStr) + " = " + valueStr;
                                            env->ReleaseStringUTFChars(fieldName, nameStr);
                                        }
                                        if (fieldName) env->DeleteLocalRef(fieldName);
                                        env->DeleteLocalRef(field);
                                    }
                                    env->DeleteLocalRef(fields);
                                    env->DeleteLocalRef(fieldClass);
                                }
                                if (env->ExceptionCheck()) {
                                    env->ExceptionClear();
                                }
                            }
                            env->DeleteLocalRef(classClass);
                        }
                        env->DeleteLocalRef(objClass);
                    }
                    env->DeleteLocalRef(jobj);
                }
            }
        }
    }
    
    xdl_close(handle);
    
    if (type_name.empty()) {
        char buf[32];
        snprintf(buf, sizeof(buf), "ArtObject<%p>", obj);
        return buf;
    }
    
    // 新格式: ArtObject<ptr> | jobject<ptr> <- TypeName | toString_result
    char buf[1024];
    if (jobj_ref != nullptr) {
        snprintf(buf, sizeof(buf), "ArtObject<%p> | jobject<%p> <- %s", obj, jobj_ref, type_name.c_str());
    } else {
        snprintf(buf, sizeof(buf), "ArtObject<%p> <- %s", obj, type_name.c_str());
    }
    std::string result = buf;
    
    // 添加 toString 结果（使用 | 分隔）
    if (!toString_result.empty()) {
        result += " | " + toString_result;
    }
    
    // // 添加字段信息
    // if (!fields_info.empty()) {
    //     result += "\n    fields:" + fields_info;
    // }

    if (type_name == "java.lang.String") {
        std::string str_value = GetJavaStringValue(obj);
        if (!str_value.empty()) {
            result.append(" <- ").append("\"").append(str_value).append("\"");
        }
    }
    
    return result;
}

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
    // 引用部分在 vregs 数组后半部分
    // 每个引用是 ObjectReference (uint32_t)，占用 4 字节（压缩引用）
    uintptr_t ref_base = reinterpret_cast<uintptr_t>(GetVRegsPtr()) + num_vregs * 4;
    uint32_t compressed_ref = *reinterpret_cast<uint32_t*>(ref_base + i * 4);
    // 将压缩引用转换为指针
    return reinterpret_cast<void*>(static_cast<uintptr_t>(compressed_ref));
}

void ShadowFrame::SetVRegReference(size_t i, void* ref) {
    if (i >= NumberOfVRegs()) {
        return;
    }
    uint32_t num_vregs = NumberOfVRegs();
    // 引用部分在 vregs 数组后半部分，每个引用占用 4 字节（压缩引用）
    uintptr_t ref_base = reinterpret_cast<uintptr_t>(GetVRegsPtr()) + num_vregs * 4;
    // 将指针转换为压缩引用（截断为 32 位）
    *reinterpret_cast<uint32_t*>(ref_base + i * 4) = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ref));
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
    logd("[*] ShadowFrame @ %p", this);
    logd("[*]   link: %p, method: %p", GetLink(), GetMethod());
    logd("[*]   dex_pc: %u (current: %u), vregs: %u", GetDexPc(), GetCurrentDexPC(), NumberOfVRegs());
    logd("[*]   dex_pc_ptr: %p, dex_instructions: %p", GetDexPcPtrValue(), GetDexInstructions());
}

void ShadowFrame::PrintVRegs(int indent) {
    uint32_t num_vregs = NumberOfVRegs();
    std::string indent_str(indent, ' ');
    
    // 获取 ins_size
    uint16_t ins_size = 0;
    ArtMethod* method = GetMethod();
    if (method != nullptr) {
        const DexFile* dex_file = method->GetDexFile();
        uint32_t code_item_offset = method->GetDexCodeItemOffset();
        if (dex_file != nullptr && code_item_offset != 0) {
            const uint8_t* data_begin = *reinterpret_cast<const uint8_t* const*>(
                reinterpret_cast<uintptr_t>(dex_file) + PointerSize + PointerSize * 2);
            if (data_begin != nullptr && !method->IsCompactDex()) {
                const uint8_t* code_item = data_begin + code_item_offset;
                ins_size = *reinterpret_cast<const uint16_t*>(code_item + 2);
            }
        }
    }
    
    logd("%s[*] VRegs (%u, ins_size=%u):", indent_str.c_str(), num_vregs, ins_size);
    for (uint32_t i = 0; i < num_vregs; i++) {
        uint32_t value = GetVReg(i);
        void* ref = GetVRegReference(i);
        
        // 确定寄存器名称
        char reg_name[16];
        if (ins_size > 0 && i >= num_vregs - ins_size) {
            uint32_t param_idx = i - (num_vregs - ins_size);
            snprintf(reg_name, sizeof(reg_name), "p%u", param_idx);
        } else {
            snprintf(reg_name, sizeof(reg_name), "v%u", i);
        }
        
        if (ref != nullptr) {
            std::string type_str = GetObjectSimpleDisp(ref);
            logd("%s  %s = 0x%08x [%s]", indent_str.c_str(), reg_name, value, type_str.c_str());
        } else if (value != 0) {
            logd("%s  %s = 0x%08x (%d)", indent_str.c_str(), reg_name, value, static_cast<int32_t>(value));
        }
    }
}

void ShadowFrame::PrintBacktrace(const int max_frames) {
    loge("[*] ShadowFrame Backtrace:");
    auto frame = this;
    int frame_index = 0;

    while (frame != nullptr && frame_index < max_frames) {
        uint32_t dex_pc = frame->GetCurrentDexPC();
        const ArtMethod *method = frame->GetMethod();
        
        if (method != nullptr) {
            std::string method_name = method->GetPrettyMethod(true);
            
            // 跳过 Android 系统类的 smali 解析（只检查类名开头）
            bool skip_smali = method_name.find("Landroid/") == 0 ||
                              method_name.find("android.") == 0;
            
            if (skip_smali) {
                logd("[*] #%d: %s", frame_index, method_name.c_str());
            } else {
                // 优先使用 ShadowFrame 中的 dex_pc_ptr
                uint16_t* dex_pc_ptr = frame->GetDexPcPtrValue();
                uint16_t* dex_instructions = frame->GetDexInstructions();
                
                const uint16_t* current_insn = nullptr;
                const uint16_t* insns_base = nullptr;
                
                if (dex_pc_ptr != nullptr) {
                    current_insn = dex_pc_ptr;
                    insns_base = dex_instructions;
                } else if (dex_instructions != nullptr) {
                    current_insn = dex_instructions + dex_pc;
                    insns_base = dex_instructions;
                } else {
                    // 从 ArtMethod 获取指令
                    const uint16_t* method_insns = method->GetDexInstructions();
                    if (method_insns != nullptr) {
                        current_insn = method_insns + dex_pc;
                        insns_base = method_insns;
                    }
                }
                
                if (current_insn != nullptr) {
                    const DexFile* dex_file = method->GetDexFile();
                    Instruction inst(current_insn);
                    std::string hex_str = inst.DumpHexLE();
                    std::string smali_str = dex_file != nullptr ? inst.DumpString(dex_file) : inst.GetOpcodeName();
                    
                    uint32_t offset = insns_base != nullptr ? static_cast<uint32_t>(current_insn - insns_base) : 0;
                    
                    logd("[*] #%d: %s", frame_index, method_name.c_str());
                    
                    // 打印上一条指令（如果存在，offset > 0 表示不是第一条指令）
                    if (offset > 0 && insns_base != nullptr) {
                        // 从方法开始遍历找到上一条指令
                        const uint16_t* prev_insn = nullptr;
                        const uint16_t* scan = insns_base;
                        while (scan < current_insn) {
                            prev_insn = scan;
                            Instruction scan_inst(scan);
                            scan += scan_inst.SizeInCodeUnits();
                        }
                        if (prev_insn != nullptr && prev_insn < current_insn) {
                            Instruction prev_inst(prev_insn);
                            uint32_t prev_offset = static_cast<uint32_t>(prev_insn - insns_base);
                            std::string prev_hex = prev_inst.DumpHexLE();
                            std::string prev_smali = dex_file != nullptr ? prev_inst.DumpString(dex_file) : prev_inst.GetOpcodeName();
                            logd("[*]     [0x%04x] %s| %s", prev_offset, prev_hex.c_str(), prev_smali.c_str());
                        }
                    }
                    
                    // 打印当前指令（高亮）
                    logd("[*]  -> [0x%04x] %s| %s", offset, hex_str.c_str(), smali_str.c_str());
                    
                    // 打印下一条指令
                    const uint16_t* next_insn = current_insn + inst.SizeInCodeUnits();
                    if (next_insn != nullptr) {
                        Instruction next_inst(next_insn);
                        uint8_t next_opcode = next_inst.Opcode();
                        // 检查是否是有效指令（不是 payload 或无效 opcode）
                        if (next_opcode != 0x00 || (next_insn[0] & 0xFF) == 0x00) {
                            uint32_t next_offset = insns_base != nullptr ? static_cast<uint32_t>(next_insn - insns_base) : 0;
                            std::string next_hex = next_inst.DumpHexLE();
                            std::string next_smali = dex_file != nullptr ? next_inst.DumpString(dex_file) : next_inst.GetOpcodeName();
                            logd("[*]     [0x%04x] %s| %s", next_offset, next_hex.c_str(), next_smali.c_str());
                        }
                    }
                } else {
                    logd("[*] #%d: %s", frame_index, method_name.c_str());
                }
                
                // 打印寄存器信息
                uint32_t num_vregs = frame->NumberOfVRegs();
                if (num_vregs > 0) {
                    // 获取 ins_size（参数寄存器数量）
                    uint16_t ins_size = 0;
                    const DexFile* dex_file = method->GetDexFile();
                    uint32_t code_item_offset = method->GetDexCodeItemOffset();
                    if (dex_file != nullptr && code_item_offset != 0) {
                        // 获取 data_begin
                        const uint8_t* data_begin = *reinterpret_cast<const uint8_t* const*>(
                            reinterpret_cast<uintptr_t>(dex_file) + PointerSize + PointerSize * 2);
                        if (data_begin != nullptr) {
                            const uint8_t* code_item = data_begin + code_item_offset;
                            // Standard DEX: registers_size(2) + ins_size(2)
                            // Compact DEX 结构不同，这里只处理标准 DEX
                            if (!method->IsCompactDex()) {
                                ins_size = *reinterpret_cast<const uint16_t*>(code_item + 2);
                            }
                        }
                    }
                    
                    // 第一行：打印寄存器值（使用 p/v 命名）
                    std::string vregs_str;
                    for (uint32_t i = 0; i < num_vregs; i++) {
                        uint32_t value = frame->GetVReg(i);
                        char buf[64];
                        // 参数寄存器在最后 ins_size 个位置
                        if (ins_size > 0 && i >= num_vregs - ins_size) {
                            uint32_t param_idx = i - (num_vregs - ins_size);
                            snprintf(buf, sizeof(buf), "p%u=0x%x", param_idx, value);
                        } else {
                            snprintf(buf, sizeof(buf), "v%u=0x%x", i, value);
                        }
                        if (!vregs_str.empty()) vregs_str += ", ";
                        vregs_str += buf;
                    }
                    logd("[*]     vregs: %s", vregs_str.c_str());
                    
                    // 第二行：打印引用类型的 simpleDisp（包含 String 值）
                    for (uint32_t i = 0; i < num_vregs; i++) {
                        uint32_t value = frame->GetVReg(i);
                        if (value == 0) continue;  // 跳过空值
                        
                        void* ref = frame->GetVRegReference(i);
                        if (ref == nullptr) continue;  // 跳过非引用类型
                        
                        // 确定寄存器名称
                        char reg_name[16];
                        if (ins_size > 0 && i >= num_vregs - ins_size) {
                            uint32_t param_idx = i - (num_vregs - ins_size);
                            snprintf(reg_name, sizeof(reg_name), "p%u", param_idx);
                        } else {
                            snprintf(reg_name, sizeof(reg_name), "v%u", i);
                        }
                        
                        std::string disp = GetObjectSimpleDisp(ref);
                        logd("[*]       %s=%s", reg_name, disp.c_str());
                    }

                }
            }
        } else {
            logd("[*] #%d: (null method)", frame_index);
        }

        frame = frame->GetLink();
        frame_index++;
    }

    if (frame_index >= max_frames && max_frames != 2) {
        logd("[*] (reached max frames limit: %d)", max_frames);
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
    ArtMethod* method = GetMethod();
    if (method == nullptr) {
        loge("[*] Current Instruction: (method is null)");
        return;
    }
    
    uint16_t* dex_instructions = GetDexInstructions();
    uint32_t dex_pc = GetCurrentDexPC();
    
    const uint16_t* current_insn = nullptr;
    if (dex_instructions != nullptr) {
        current_insn = dex_instructions + dex_pc;
    } else {
        current_insn = method->GetDexInstructions();
    }
    
    if (current_insn == nullptr) {
        loge("[*] Current Instruction: (instructions not available)");
        return;
    }
    
    Instruction inst(current_insn);
    const DexFile* dex_file = method->GetDexFile();
    
    loge("[*] Current Instruction at dex_pc 0x%04x:", dex_pc);
    loge("[*]   %s | %s", 
         inst.DumpHexLE().c_str(),
         dex_file != nullptr ? inst.DumpString(dex_file).c_str() : inst.GetOpcodeName());
}

// 将 mirror::Object* (ArtObject) 转换为 jobject
// 使用 JNIEnvExt::NewLocalRef
// _ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE
jobject art::ArtObjectToJobject(JNIEnv* env, void* art_obj) {
    if (env == nullptr || art_obj == nullptr) {
        return nullptr;
    }
    
    void* handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        logw("[!] ArtObjectToJobject: failed to open libart.so");
        return nullptr;
    }
    
    // jobject JNIEnvExt::NewLocalRef(mirror::Object* obj)
    // __int64 __fastcall art::JNIEnvExt::NewLocalRef(art::JNIEnvExt *__hidden this, art::mirror::Object *)
    typedef jobject (*NewLocalRefFunc)(JNIEnv*, void*);
    auto func = reinterpret_cast<NewLocalRefFunc>(
        xdl_sym(handle, "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE", nullptr));
    
    if (func == nullptr) {
        xdl_close(handle);
        logw("[!] ArtObjectToJobject: failed to find NewLocalRef symbol");
        return nullptr;
    }
    
    jobject result = func(env, art_obj);
    xdl_close(handle);
    
    return result;
}
