#include "jvmti_helper.h"
#include "stacktrace_helper.h"
#include "log.h"
#include "xdl.h"
#include "art/art_method.h"
#include "art/shadow_frame.h"
#include <dlfcn.h>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <vector>
#include <slicer/reader.h>
#include <slicer/writer.h>
#include <slicer/dex_ir.h>
#include <slicer/code_ir.h>
#include <slicer/instrumentation.h>
#include <slicer/dex_bytecode.h>
#include <slicer/dex_ir_builder.h>
#include <slicer/buffer.h>

#include "crashhelper_dex.h"

// 临时 JVMTI Agent 文件名（不带扩展名）
#define TEMP_JVMTI_AGENT_NAME "uinj_jvmti"

// 当前堆栈打印模式（默认打印 Native 堆栈）
static StackTraceMode g_stack_trace_mode = STACK_TRACE_NULL;

// JVMTI 全局变量
// 注意：在动态链接场景下，确保符号可见性
__attribute__((visibility("default"))) jvmtiEnv* g_jvmti_env = nullptr;

// 缓存从 .so 中加载的 g_jvmti_env 指针的地址
static jvmtiEnv** g_jvmti_env_from_so = nullptr;

// JDWP 状态
enum JdwpState {
    JDWP_UNKNOWN,
    JDWP_ON,
    JDWP_OFF
};

static JdwpState g_original_jdwp_state = JDWP_UNKNOWN;

// 获取全局 JVMTI 环境
jvmtiEnv* GetGlobalJvmtiEnv() {
    if (g_jvmti_env_from_so != nullptr) {
        return *g_jvmti_env_from_so;
    }

    // 直接从临时 JVMTI agent 中查找 g_jvmti_env 符号
    // 这个 so 是我们在 AttachJvmtiAgent 中复制并加载的
    void* handle = xdl_open(TEMP_JVMTI_AGENT_NAME, XDL_DEFAULT);
    if (handle == nullptr) {
        loge("[!] GetGlobalJvmtiEnv: failed to open %s", TEMP_JVMTI_AGENT_NAME);
        return g_jvmti_env;
    }
    
    logd("[*] GetGlobalJvmtiEnv: opened %s handle: %p", TEMP_JVMTI_AGENT_NAME, handle);
    
    // 从 .so 中获取 g_jvmti_env 符号
    g_jvmti_env_from_so = static_cast<jvmtiEnv**>(
        xdl_sym(handle, "g_jvmti_env", nullptr));
    xdl_close(handle);
    
    if (g_jvmti_env_from_so != nullptr) {
        logd("[*] GetGlobalJvmtiEnv: loaded g_jvmti_env from %s: %p",
             TEMP_JVMTI_AGENT_NAME, *g_jvmti_env_from_so);
        return *g_jvmti_env_from_so;
    } else {
        loge("[!] GetGlobalJvmtiEnv: failed to find g_jvmti_env symbol in %s", TEMP_JVMTI_AGENT_NAME);
    }

    return g_jvmti_env;
}

// 设置异常回调的堆栈打印模式
void SetStackTraceMode(StackTraceMode mode) {
    g_stack_trace_mode = mode;
    const char* mode_str = "";
    switch (mode) {
        case STACK_TRACE_NATIVE:
            mode_str = "NATIVE";
            break;
        case STACK_TRACE_JAVA:
            mode_str = "JAVA";
            break;
        case STACK_TRACE_BOTH:
            mode_str = "BOTH";
            break;
    }
    logd("[*] Stack trace mode set to: %s", mode_str);
}

// 获取当前的堆栈打印模式
StackTraceMode GetStackTraceMode() {
    return g_stack_trace_mode;
}

// 设置调试状态（允许或禁止调试）
bool SetDebuggableRelease(bool allowDebug) {
    logd("[*] SetDebuggableRelease: attempting to set debug state to %d", allowDebug);
    
    void *handle = xdl_open("libart.so", XDL_DEFAULT);
    if (handle == nullptr) {
        loge("[!] Failed to open libart.so");
        return false;
    }
    
    // 首次调用时，保存原始的 JDWP 状态
    if (g_original_jdwp_state == JDWP_UNKNOWN) {
        // art::Dbg::IsJdwpAllowed()
        auto IsJdwpAllowed = reinterpret_cast<bool (*)()>(
            xdl_sym(handle, "_ZN3art3Dbg13IsJdwpAllowedEv", nullptr));
        
        if (IsJdwpAllowed != nullptr) {
            bool jdwpAllowed = IsJdwpAllowed();
            g_original_jdwp_state = jdwpAllowed ? JDWP_ON : JDWP_OFF;
            logd("[*] Original JDWP state: %s", jdwpAllowed ? "ON" : "OFF");
        } else {
            logd("[*] IsJdwpAllowed not found, assuming JDWP is OFF");
            g_original_jdwp_state = JDWP_OFF;
        }
    }
    
    // 如果原始状态是 OFF，则设置新的状态
    if (g_original_jdwp_state == JDWP_OFF) {
        // art::Dbg::SetJdwpAllowed(bool)
        auto SetJdwpAllowed = reinterpret_cast<void (*)(bool)>(
            xdl_sym(handle, "_ZN3art3Dbg14SetJdwpAllowedEb", nullptr));
        
        if (SetJdwpAllowed != nullptr) {
            SetJdwpAllowed(allowDebug);
            logd("[*] JDWP state set to: %s", allowDebug ? "allowed" : "disallowed");
        } else {
            loge("[!] SetJdwpAllowed function not found");
            xdl_close(handle);
            return false;
        }
    } else {
        logd("[*] Original JDWP was ON, skipping state change");
    }
    
    xdl_close(handle);
    return true;
}

// 获取应用的缓存目录
static std::string GetAppCacheDir(JNIEnv* jni) {
    if (jni == nullptr) {
        return "";
    }
    
    try {
        // 获取 ActivityThread 类
        jclass activityThreadClass = jni->FindClass("android/app/ActivityThread");
        if (activityThreadClass == nullptr) {
            jni->ExceptionClear();
            loge("[!] Failed to find ActivityThread class");
            return "";
        }
        
        // 获取 currentApplication() 方法
        jmethodID currentApplicationMethod = jni->GetStaticMethodID(
            activityThreadClass, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationMethod == nullptr) {
            jni->ExceptionClear();
            jni->DeleteLocalRef(activityThreadClass);
            loge("[!] Failed to find currentApplication method");
            return "";
        }
        
        // 调用 currentApplication() 获取 Application 对象
        jobject application = jni->CallStaticObjectMethod(activityThreadClass, currentApplicationMethod);
        jni->DeleteLocalRef(activityThreadClass);
        
        if (application == nullptr) {
            jni->ExceptionClear();
            loge("[!] Failed to get Application object");
            return "";
        }
        
        // 获取 Context 类
        jclass contextClass = jni->FindClass("android/content/Context");
        if (contextClass == nullptr) {
            jni->ExceptionClear();
            jni->DeleteLocalRef(application);
            loge("[!] Failed to find Context class");
            return "";
        }
        
        // 获取 getCacheDir() 方法
        jmethodID getCacheDirMethod = jni->GetMethodID(
            contextClass, "getCacheDir", "()Ljava/io/File;");
        if (getCacheDirMethod == nullptr) {
            jni->ExceptionClear();
            jni->DeleteLocalRef(contextClass);
            jni->DeleteLocalRef(application);
            loge("[!] Failed to find getCacheDir method");
            return "";
        }
        
        // 调用 getCacheDir()
        jobject cacheDir = jni->CallObjectMethod(application, getCacheDirMethod);
        jni->DeleteLocalRef(contextClass);
        jni->DeleteLocalRef(application);
        
        if (cacheDir == nullptr) {
            jni->ExceptionClear();
            loge("[!] Failed to get cache directory");
            return "";
        }
        
        // 获取 File 类
        jclass fileClass = jni->FindClass("java/io/File");
        if (fileClass == nullptr) {
            jni->ExceptionClear();
            jni->DeleteLocalRef(cacheDir);
            loge("[!] Failed to find File class");
            return "";
        }
        
        // 获取 getAbsolutePath() 方法
        jmethodID getAbsolutePathMethod = jni->GetMethodID(
            fileClass, "getAbsolutePath", "()Ljava/lang/String;");
        if (getAbsolutePathMethod == nullptr) {
            jni->ExceptionClear();
            jni->DeleteLocalRef(fileClass);
            jni->DeleteLocalRef(cacheDir);
            loge("[!] Failed to find getAbsolutePath method");
            return "";
        }
        
        // 调用 getAbsolutePath()
        jstring pathString = (jstring)jni->CallObjectMethod(cacheDir, getAbsolutePathMethod);
        jni->DeleteLocalRef(fileClass);
        jni->DeleteLocalRef(cacheDir);
        
        if (pathString == nullptr) {
            jni->ExceptionClear();
            loge("[!] Failed to get absolute path");
            return "";
        }
        
        // 转换为 C++ string
        const char* pathChars = jni->GetStringUTFChars(pathString, nullptr);
        std::string cachePath(pathChars);
        jni->ReleaseStringUTFChars(pathString, pathChars);
        jni->DeleteLocalRef(pathString);
        
        logd("[*] App cache directory: %s", cachePath.c_str());
        return cachePath;
        
    } catch (...) {
        jni->ExceptionClear();
        loge("[!] Exception while getting cache directory");
        return "";
    }
}

// 复制文件到临时目录
static std::string CopyToTempFile(JNIEnv* env, const char* sourcePath, const char* tempFileName) {
    if (sourcePath == nullptr || tempFileName == nullptr) {
        loge("[!] CopyToTempFile: invalid parameters");
        return "";
    }
    
    // 获取缓存目录
    std::string cache_dir = GetAppCacheDir(env);
    if (cache_dir.empty()) {
        loge("[!] Failed to get cache directory");
        return "";
    }
    
    std::string temp_path = cache_dir + "/" + tempFileName;
    logd("[*] Copying %s to %s", sourcePath, temp_path.c_str());
    
    // 打开源文件
    FILE* src = fopen(sourcePath, "rb");
    if (src == nullptr) {
        loge("[!] Failed to open source file: %s (errno: %d - %s)", sourcePath, errno, strerror(errno));
        return "";
    }
    
    // 打开目标文件
    FILE* dst = fopen(temp_path.c_str(), "wb");
    if (dst == nullptr) {
        loge("[!] Failed to open destination file: %s (errno: %d - %s)", temp_path.c_str(), errno, strerror(errno));
        fclose(src);
        return "";
    }
    
    // 复制文件内容
    char buffer[8192];
    size_t bytes_read;
    size_t total_copied = 0;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        size_t bytes_written = fwrite(buffer, 1, bytes_read, dst);
        if (bytes_written != bytes_read) {
            loge("[!] Failed to write to destination file");
            fclose(src);
            fclose(dst);
            remove(temp_path.c_str());
            return "";
        }
        total_copied += bytes_written;
    }
    
    fclose(src);
    fclose(dst);
    
    logd("[*] Successfully copied %zu bytes to %s", total_copied, temp_path.c_str());
    return temp_path;
}

// 删除临时文件
static void DeleteTempFile(const char* filePath) {
    if (filePath == nullptr || strlen(filePath) == 0) {
        return;
    }
    
    if (remove(filePath) == 0) {
        logd("[*] Deleted temp file: %s", filePath);
    } else {
        loge("[!] Failed to delete temp file: %s (errno: %d - %s)", filePath, errno, strerror(errno));
    }
}

// 获取当前 so 文件的路径
std::string GetCurrentSoPath() {
    Dl_info info;
    // 使用当前函数的地址来获取 so 路径
    if (dladdr((void*)GetCurrentSoPath, &info) != 0) {
        if (info.dli_fname != nullptr) {
            return {info.dli_fname};
        }
    }
    loge("[!] Failed to get current SO path");
    return "";
}

// 动态附加 JVMTI Agent
bool AttachJvmtiAgent(JNIEnv* env, const char* agentPath, jobject classLoader) {
    if (env == nullptr || agentPath == nullptr) {
        loge("[!] AttachJvmtiAgent: invalid parameters");
        return false;
    }
    
    logd("[*] AttachJvmtiAgent: attempting to attach agent: %s", agentPath);

    // 复制 agent 文件到缓存目录并重命名
    std::string temp_agent_path = CopyToTempFile(env, agentPath, TEMP_JVMTI_AGENT_NAME);
    if (temp_agent_path.empty()) {
        loge("[!] Failed to copy agent to temp directory");
        return false;
    }
    
    const char* final_agent_path = temp_agent_path.c_str();
    logd("[*] Using temp agent path: %s", final_agent_path);

    // https://cs.android.com/android/platform/superproject/main/+/main:art/runtime/native/dalvik_system_VMDebug.cc;l=574;bpv=0;bpt=0
    // 查找 dalvik.system.VMDebug 类
    jclass vmDebugClass = env->FindClass("dalvik/system/VMDebug");
    if (vmDebugClass == nullptr) {
        loge("[!] Failed to find dalvik.system.VMDebug class");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        DeleteTempFile(final_agent_path);
        return false;
    }
    
    // attachAgent 是静态方法，需要使用 GetStaticMethodID
    // public static void attachAgent(String agent, ClassLoader classLoader)
    jmethodID attachAgentMethod = env->GetStaticMethodID(
        vmDebugClass, 
        "attachAgent", 
        "(Ljava/lang/String;Ljava/lang/ClassLoader;)V"
    );
    
    if (attachAgentMethod == nullptr) {
        loge("[!] Failed to find attachAgent method");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        env->DeleteLocalRef(vmDebugClass);
        DeleteTempFile(final_agent_path);
        return false;
    }
    
    // 创建 agent 路径字符串
    jstring agentPathStr = env->NewStringUTF(final_agent_path);
    if (agentPathStr == nullptr) {
        loge("[!] Failed to create agent path string");
        env->DeleteLocalRef(vmDebugClass);
        DeleteTempFile(final_agent_path);
        return false;
    }
    
    logd("[*] VMDebug | cls:%p | mid:%p", vmDebugClass, attachAgentMethod);
    logd("[*] Attaching JVMTI agent: %s with classLoader: %p", final_agent_path, classLoader);
    
    // 调用 attachAgent 方法
    env->CallStaticVoidMethod(
        vmDebugClass, 
        attachAgentMethod, 
        agentPathStr, 
        classLoader
    );
    
    // 检查是否有异常
    bool success = true;
    if (env->ExceptionCheck()) {
        loge("[!] Exception occurred while attaching agent");
        env->ExceptionDescribe();
        env->ExceptionClear();
        success = false;
    } else {
        logd("[*] JVMTI agent attached successfully");
    }
    
    // 清理本地引用
    env->DeleteLocalRef(agentPathStr);
    env->DeleteLocalRef(vmDebugClass);
    
    // 删除临时文件
    DeleteTempFile(final_agent_path);
    
    return success;
}

// 创建 JVMTI 环境
jvmtiEnv* CreateJvmtiEnv(JavaVM *vm) {
    if (vm == nullptr) {
        loge("[!] CreateJvmtiEnv: vm is nullptr");
        return nullptr;
    }
    
    jvmtiEnv *jvmti_env = nullptr;
    jint result = vm->GetEnv((void **) &jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK) {
        loge("[!] Failed to get JVMTI environment, error: %d", result);
        return nullptr;
    }

    return jvmti_env;
}

// 设置 JVMTI 所需的能力
int SetJvmtiCapabilities(jvmtiEnv *jvmti) {
    if (jvmti == nullptr) {
        loge("[!] SetJvmtiCapabilities: jvmti is nullptr");
        return JVMTI_ERROR_NULL_POINTER;
    }
    
    jvmtiCapabilities caps = {0};
    jvmtiError error = jvmti->GetPotentialCapabilities(&caps);
    logd("[*] GetPotentialCapabilities: retransform=%d, retransform_any=%d, native_prefix=%d, exception=%d, error=%d", 
         caps.can_retransform_classes, caps.can_retransform_any_class, 
         caps.can_set_native_method_prefix, caps.can_generate_exception_events, error);
    
    jvmtiCapabilities newCaps = {0};
    newCaps.can_retransform_classes = 1;
    if (caps.can_set_native_method_prefix) {
        newCaps.can_set_native_method_prefix = 1;
    }
    // 添加异常事件能力
    if (caps.can_generate_exception_events) {
        newCaps.can_generate_exception_events = 1;
        logd("[*] Enabling exception event capability");
    }
    
    error = jvmti->AddCapabilities(&newCaps);
    if (error != JVMTI_ERROR_NONE) {
        loge("[!] Failed to add JVMTI capabilities, error: %d", error);
        return error;
    }
    
    logd("[*] JVMTI capabilities added successfully");
    return JVMTI_ERROR_NONE;
}

// 打印操作数信息的辅助函数
static void PrintOperand(lir::Operand* operand, size_t index) {
    if (auto vreg = dynamic_cast<lir::VReg*>(operand)) {
        logd("[*]             operand[%zu]: VReg v%u", index, vreg->reg);
    } else if (auto vreg_pair = dynamic_cast<lir::VRegPair*>(operand)) {
        logd("[*]             operand[%zu]: VRegPair v%u:v%u", index, vreg_pair->base_reg, vreg_pair->base_reg + 1);
    } else if (auto vreg_range = dynamic_cast<lir::VRegRange*>(operand)) {
        logd("[*]             operand[%zu]: VRegRange v%u..v%u (count: %d)", 
             index, vreg_range->base_reg, vreg_range->base_reg + vreg_range->count - 1, vreg_range->count);
    } else if (auto vreg_list = dynamic_cast<lir::VRegList*>(operand)) {
        std::string regs = "VRegList {";
        for (size_t i = 0; i < vreg_list->registers.size(); ++i) {
            if (i > 0) regs += ", ";
            regs += "v" + std::to_string(vreg_list->registers[i]);
        }
        regs += "}";
        logd("[*]             operand[%zu]: %s", index, regs.c_str());
    } else if (auto str = dynamic_cast<lir::String*>(operand)) {
        logd("[*]             operand[%zu]: String \"%s\"", index, str->ir_string->c_str());
    } else if (auto type = dynamic_cast<lir::Type*>(operand)) {
        logd("[*]             operand[%zu]: Type %s", index, type->ir_type->descriptor->c_str());
    } else if (auto field = dynamic_cast<lir::Field*>(operand)) {
        logd("[*]             operand[%zu]: Field %s.%s:%s", 
             index,
             field->ir_field->parent->descriptor->c_str(),
             field->ir_field->name->c_str(),
             field->ir_field->type->descriptor->c_str());
    } else if (auto method_ref = dynamic_cast<lir::Method*>(operand)) {
        logd("[*]             operand[%zu]: Method %s.%s%s", 
             index,
             method_ref->ir_method->parent->descriptor->c_str(),
             method_ref->ir_method->name->c_str(),
             method_ref->ir_method->prototype->Signature().c_str());
    } else if (auto const32 = dynamic_cast<lir::Const32*>(operand)) {
        logd("[*]             operand[%zu]: Const32 0x%x (%d)", 
             index, const32->u.u4_value, const32->u.s4_value);
    } else if (auto const64 = dynamic_cast<lir::Const64*>(operand)) {
        logd("[*]             operand[%zu]: Const64 0x%llx (%lld)", 
             index, const64->u.u8_value, const64->u.s8_value);
    } else if (auto label = dynamic_cast<lir::CodeLocation*>(operand)) {
        logd("[*]             operand[%zu]: CodeLocation -> Label %d", index, label->label->id);
    } else {
        logd("[*]             operand[%zu]: (unknown operand type)", index);
    }
}

// 打印方法的字节码指令
static void PrintMethodBytecode(ir::EncodedMethod* method, std::shared_ptr<ir::DexFile> dex_ir, const char* method_type) {
    if (method == nullptr || method->decl == nullptr) return;
    
    std::string methodName = method->decl->name->c_str();
    std::string methodProto = method->decl->prototype->Signature();
    logd("[*]   %s: %s%s", method_type, methodName.c_str(), methodProto.c_str());
    
    if (method->code) {
        logd("[*]     Code registers: %u", method->code->registers);
        logd("[*]     Ins: %u, Outs: %u", method->code->ins_count, method->code->outs_count);
        logd("[*]     Instructions size: %zu", method->code->instructions.size());
        
        try {
            // 使用 CodeIr 来解析指令
            lir::CodeIr code_ir(method, dex_ir);
            
            logd("[*]     Disassembled instructions:");
            int instr_index = 0;
            for (auto instr : code_ir.instructions) {
                if (auto bytecode = dynamic_cast<lir::Bytecode*>(instr)) {
                    logd("[*]       [%04d] offset: 0x%04x, opcode: 0x%02x (operands: %zu)", 
                         instr_index++, bytecode->offset, bytecode->opcode, bytecode->operands.size());
                    
                    // 打印操作数信息
                    for (size_t i = 0; i < bytecode->operands.size(); ++i) {
                        PrintOperand(bytecode->operands[i], i);
                    }
                } else if (auto label = dynamic_cast<lir::Label*>(instr)) {
                    logd("[*]       [%04d] Label_%d: (offset: 0x%04x)", instr_index++, label->id, label->offset);
                } else if (auto try_begin = dynamic_cast<lir::TryBlockBegin*>(instr)) {
                    logd("[*]       [%04d] TryBlockBegin_%d", instr_index++, try_begin->id);
                } else if (auto try_end = dynamic_cast<lir::TryBlockEnd*>(instr)) {
                    logd("[*]       [%04d] TryBlockEnd (try_begin: %d)", instr_index++, try_end->try_begin->id);
                    for (auto& handler : try_end->handlers) {
                        logd("[*]             catch %s -> Label_%d", 
                             handler.ir_type ? handler.ir_type->descriptor->c_str() : "(all)",
                             handler.label->id);
                    }
                    if (try_end->catch_all) {
                        logd("[*]             catch_all -> Label_%d", try_end->catch_all->id);
                    }
                } else if (auto packed_switch = dynamic_cast<lir::PackedSwitchPayload*>(instr)) {
                    logd("[*]       [%04d] PackedSwitch (first_key: %d, targets: %zu)", 
                         instr_index++, packed_switch->first_key, packed_switch->targets.size());
                } else if (auto sparse_switch = dynamic_cast<lir::SparseSwitchPayload*>(instr)) {
                    logd("[*]       [%04d] SparseSwitch (cases: %zu)", 
                         instr_index++, sparse_switch->switch_cases.size());
                } else if (auto array_data = dynamic_cast<lir::ArrayData*>(instr)) {
                    logd("[*]       [%04d] ArrayData (size: %zu bytes)", 
                         instr_index++, array_data->data.size());
                } else {
                    logd("[*]       [%04d] (other instruction type)", instr_index++);
                }
            }
        } catch (const std::exception& e) {
            loge("[!] Exception while disassembling method %s: %s", methodName.c_str(), e.what());
        }
    } else {
        logd("[*]     (no code - abstract or native method)");
    }
}

// 打印类的所有方法
static void PrintClassMethods(ir::Class* ir_class, std::shared_ptr<ir::DexFile> dex_ir) {
    if (ir_class == nullptr || ir_class->type == nullptr) {
        return;
    }
    
    std::string fullClassName = ir_class->type->Decl();
    logd("[*] ========================================");
    logd("[*] Class: %s", fullClassName.c_str());
    logd("[*] Access flags: 0x%x", ir_class->access_flags);
    
    if (ir_class->super_class) {
        logd("[*] Super class: %s", ir_class->super_class->descriptor->c_str());
    }
    
    if (ir_class->interfaces && !ir_class->interfaces->types.empty()) {
        logd("[*] Interfaces:");
        for (auto& iface : ir_class->interfaces->types) {
            logd("[*]   - %s", iface->descriptor->c_str());
        }
    }
    
    // 打印静态字段
    if (!ir_class->static_fields.empty()) {
        logd("[*] Static fields:");
        for (auto& field : ir_class->static_fields) {
            if (field && field->decl) {
                logd("[*]   - %s:%s (flags: 0x%x)", 
                     field->decl->name->c_str(),
                     field->decl->type->descriptor->c_str(),
                     field->access_flags);
            }
        }
    }
    
    // 打印实例字段
    if (!ir_class->instance_fields.empty()) {
        logd("[*] Instance fields:");
        for (auto& field : ir_class->instance_fields) {
            if (field && field->decl) {
                logd("[*]   - %s:%s (flags: 0x%x)", 
                     field->decl->name->c_str(),
                     field->decl->type->descriptor->c_str(),
                     field->access_flags);
            }
        }
    }
    
    // 打印直接方法（构造函数、静态方法、私有方法）
    if (!ir_class->direct_methods.empty()) {
        logd("[*] Direct methods (%zu):", ir_class->direct_methods.size());
        for (auto& method : ir_class->direct_methods) {
            PrintMethodBytecode(method, dex_ir, "DirectMethod");
        }
    }
    
    // 打印虚方法（public/protected 实例方法）
    if (!ir_class->virtual_methods.empty()) {
        logd("[*] Virtual methods (%zu):", ir_class->virtual_methods.size());
        for (auto& method : ir_class->virtual_methods) {
            PrintMethodBytecode(method, dex_ir, "VirtualMethod");
        }
    }
    
    logd("[*] ========================================");
}

// 检查指令是否是结果移动指令（必须紧跟在调用指令后）
static bool IsResultMoveInstruction(dex::Opcode opcode) {
    return opcode == dex::OP_MOVE_RESULT ||
           opcode == dex::OP_MOVE_RESULT_WIDE ||
           opcode == dex::OP_MOVE_RESULT_OBJECT ||
           opcode == dex::OP_MOVE_EXCEPTION;
}

// 创建 CrashHelper.triggerCrash() 方法声明的引用
// 引用外部已存在的类: Lcom/inject/utils/CrashHelper;
// 方法: public static void triggerCrash()V
// 使用 ir::Builder 来正确创建方法引用（参考 dexter slicer instrumentation.cc）
static ir::MethodDecl* CreateCrashHelperMethodRef(std::shared_ptr<ir::DexFile> dex_ir) {
    ir::Builder builder(dex_ir);
    
    // 使用 Builder 创建方法声明
    // 这是 dexter 推荐的方式，会正确处理字符串、类型、原型的创建和索引分配
    auto ir_method_decl = builder.GetMethodDecl(
        builder.GetAsciiString("triggerCrash"),                    // 方法名
        builder.GetProto(                                          // 原型 ()V
            builder.GetType("V"),                                  // 返回类型 void
            builder.GetTypeList(std::vector<ir::Type*>())          // 无参数
        ),
        builder.GetType("Lcom/inject/utils/CrashHelper;")          // 所属类
    );
    
    logd("[*] Created reference to CrashHelper.triggerCrash() using ir::Builder");
    logd("[*]   Method: %s.%s%s", 
         ir_method_decl->parent->descriptor->c_str(),
         ir_method_decl->name->c_str(),
         ir_method_decl->prototype->Signature().c_str());
    
    return ir_method_decl;
}

// 为方法的每条指令前插入调用 CrashHelper.triggerCrash()
// 参考 dexter slicer instrumentation.cc 中的 EntryHook::Apply 实现
static void InsertCrashHelperCallBeforeEachInstruction(ir::EncodedMethod* method, 
                                                         std::shared_ptr<ir::DexFile> dex_ir,
                                                         ir::MethodDecl* crash_method_decl) {
    if (method == nullptr || method->code == nullptr || crash_method_decl == nullptr) {
        return;
    }
    
    std::string methodName = method->decl->name->c_str();
    std::string methodProto = method->decl->prototype->Signature();
    logd("[*] Inserting CrashHelper.triggerCrash() calls in method: %s%s", 
         methodName.c_str(), methodProto.c_str());
    
    try {
        // 创建 CodeIr - 这会反汇编方法的字节码
        lir::CodeIr code_ir(method, dex_ir);
        
        // 收集所有可以插入指令的字节码位置
        // 注意：不能在 move-result* 指令前插入，因为它们必须紧跟在 invoke 指令后
        std::vector<lir::Bytecode*> insertion_points;
        
        for (auto instr : code_ir.instructions) {
            if (auto bytecode = dynamic_cast<lir::Bytecode*>(instr)) {
                // 跳过 NOP 指令
                if (bytecode->opcode == dex::OP_NOP) {
                    continue;
                }
                
                // 跳过 move-result* 指令（必须紧跟在调用指令后）
                if (IsResultMoveInstruction(bytecode->opcode)) {
                    continue;
                }
                
                insertion_points.push_back(bytecode);
            }
        }
        
        logd("[*]   Found %zu valid insertion points", insertion_points.size());
        
        if (insertion_points.empty()) {
            logd("[*]   No valid insertion points, skipping method");
            return;
        }
        
        // 创建方法引用（使用 code_ir 的 Alloc，确保生命周期正确）
        // 参考 instrumentation.cc 中的做法
        auto hook_method = code_ir.Alloc<lir::Method>(crash_method_decl, crash_method_decl->orig_index);
        
        // 在每个插入点前插入 invoke-static CrashHelper.triggerCrash()
        int inserted_count = 0;
        for (auto bytecode : insertion_points) {
            // 创建 invoke-static 指令 (35c 格式)
            // 格式: invoke-static {vC, vD, vE, vF, vG}, method@BBBB
            // 对于无参数调用，使用空的 VRegList
            auto invoke_crash = code_ir.Alloc<lir::Bytecode>();
            invoke_crash->opcode = dex::OP_INVOKE_STATIC;
            
            // 创建空的寄存器列表（无参数）
            auto vreg_list = code_ir.Alloc<lir::VRegList>();
            
            // 操作数顺序：先寄存器列表，后方法引用
            invoke_crash->operands.push_back(vreg_list);
            invoke_crash->operands.push_back(hook_method);
            
            // 在目标指令前插入
            code_ir.instructions.InsertBefore(bytecode, invoke_crash);
            inserted_count++;
        }
        
        // 重新组装字节码 - 这会更新 method->code
        code_ir.Assemble();
        
        logd("[*]   Successfully inserted %d CrashHelper.triggerCrash() calls in %s", 
             inserted_count, methodName.c_str());
        
    } catch (const std::exception& e) {
        loge("[!] Exception while inserting crash calls in method %s: %s", 
             methodName.c_str(), e.what());
    } catch (...) {
        loge("[!] Unknown exception while inserting crash calls in method %s", 
             methodName.c_str());
    }
}

// JVMTI 内存分配器
class JvmtiAllocator : public dex::Writer::Allocator {
public:
    explicit JvmtiAllocator(jvmtiEnv* jvmti) : jvmti_(jvmti) {}
    
    virtual void* Allocate(size_t size) override {
        unsigned char* mem = nullptr;
        jvmtiError error = jvmti_->Allocate(size, &mem);
        if (error != JVMTI_ERROR_NONE) {
            loge("[!] JVMTI Allocate failed: %d", error);
            return nullptr;
        }
        return mem;
    }
    
    virtual void Free(void* ptr) override {
        if (ptr != nullptr) {
            jvmti_->Deallocate(static_cast<unsigned char*>(ptr));
        }
    }
    
private:
    jvmtiEnv* jvmti_;
};

// 加载 CrashHelper.dex 到 ClassLoader
static bool LoadCrashHelperDex(JNIEnv* jni, jobject loader) {
    static bool loaded = false;
    
    // 只加载一次
    if (loaded) {
        return true;
    }
    
    logd("[*] Loading CrashHelper.dex into ClassLoader...");
    
    if (loader == nullptr) {
        loge("[!] ClassLoader is null");
        return false;
    }
    
    try {
        // 1. 获取应用缓存目录
        std::string cache_dir = GetAppCacheDir(jni);
        if (cache_dir.empty()) {
            loge("[!] Failed to get app cache directory");
            return false;
        }
        
        logd("[*] App cache directory: %s", cache_dir.c_str());
        
        // 2. 保存 DEX 文件到缓存目录
        std::string dex_path = cache_dir + "/CrashHelper.dex";
        FILE* dex_file = fopen(dex_path.c_str(), "wb");
        if (dex_file == nullptr) {
            loge("[!] Failed to create DEX file: %s (errno: %d - %s)", 
                 dex_path.c_str(), errno, strerror(errno));
            return false;
        }
        
        size_t written = fwrite(crashhelper_dex, 1, crashhelper_dex_size, dex_file);
        fclose(dex_file);
        
        if (written != crashhelper_dex_size) {
            loge("[!] Failed to write complete DEX file: wrote %zu/%u bytes", 
                 written, crashhelper_dex_size);
            return false;
        }
        
        logd("[*] Saved CrashHelper.dex to: %s (%u bytes)", dex_path.c_str(), crashhelper_dex_size);
        
        // 3. 获取 ClassLoader 的类
        jclass classLoaderClass = jni->GetObjectClass(loader);
        if (classLoaderClass == nullptr) {
            loge("[!] Failed to get ClassLoader class");
            return false;
        }
        
        // 4. 尝试使用 BaseDexClassLoader.addDexPath() 方法（Android 8.0+）
        jclass baseDexClassLoaderClass = jni->FindClass("dalvik/system/BaseDexClassLoader");
        if (baseDexClassLoaderClass != nullptr) {
            jmethodID addDexPathMethod = jni->GetMethodID(
                baseDexClassLoaderClass,
                "addDexPath",
                "(Ljava/lang/String;)V"
            );
            
            if (addDexPathMethod != nullptr) {
                logd("[*] Using BaseDexClassLoader.addDexPath()");
                jstring jDexPath = jni->NewStringUTF(dex_path.c_str());
                jni->CallVoidMethod(loader, addDexPathMethod, jDexPath);
                jni->DeleteLocalRef(jDexPath);
                
                if (jni->ExceptionCheck()) {
                    loge("[!] Exception while calling addDexPath");
                    jni->ExceptionDescribe();
                    jni->ExceptionClear();
                } else {
                    logd("[*] Successfully added DEX path to ClassLoader");
                    
                    // 验证类是否可以加载
                    jmethodID loadClassMethod = jni->GetMethodID(
                        classLoaderClass,
                        "loadClass",
                        "(Ljava/lang/String;)Ljava/lang/Class;"
                    );
                    
                    if (loadClassMethod != nullptr) {
                        jstring jClassName = jni->NewStringUTF("com.inject.utils.CrashHelper");
                        jclass crashHelperClass = static_cast<jclass>(
                            jni->CallObjectMethod(loader, loadClassMethod, jClassName)
                        );
                        
                        if (jni->ExceptionCheck()) {
                            loge("[!] Exception while loading CrashHelper class");
                            jni->ExceptionDescribe();
                            jni->ExceptionClear();
                        } else if (crashHelperClass != nullptr) {
                            logd("[*] Successfully loaded CrashHelper class: %p", crashHelperClass);
                            
                            // 验证 triggerCrash 方法
                            jmethodID triggerCrashMethod = jni->GetStaticMethodID(
                                crashHelperClass,
                                "triggerCrash",
                                "()V"
                            );
                            
                            if (triggerCrashMethod != nullptr) {
                                logd("[*] Verified triggerCrash method exists");
                            } else {
                                loge("[!] triggerCrash method not found");
                                jni->ExceptionClear();
                            }
                            
                            jni->DeleteLocalRef(crashHelperClass);
                        }
                        
                        jni->DeleteLocalRef(jClassName);
                    }
                    
                    jni->DeleteLocalRef(baseDexClassLoaderClass);
                    jni->DeleteLocalRef(classLoaderClass);

                    loaded = true;
                    return true;
                }
            } else {
                logd("[*] addDexPath method not found, trying alternative approach");
                jni->ExceptionClear();
            }
            
            jni->DeleteLocalRef(baseDexClassLoaderClass);
        } else {
            jni->ExceptionClear();
        }
        
        // 5. 备用方案：通过反射操作 pathList（适用于旧版本 Android）
        logd("[*] Using reflection to add DEX to pathList");
        
        // 获取 pathList 字段
        jfieldID pathListField = jni->GetFieldID(
            classLoaderClass,
            "pathList",
            "Ldalvik/system/DexPathList;"
        );
        
        if (pathListField == nullptr) {
            loge("[!] Failed to find pathList field");
            jni->ExceptionClear();
            jni->DeleteLocalRef(classLoaderClass);
            return false;
        }
        
        jobject pathList = jni->GetObjectField(loader, pathListField);
        if (pathList == nullptr) {
            loge("[!] pathList is null");
            jni->DeleteLocalRef(classLoaderClass);
            return false;
        }
        
        // 获取 DexPathList 类
        jclass dexPathListClass = jni->GetObjectClass(pathList);
        
        // 调用 addDexPath 方法
        jmethodID addDexPathMethod = jni->GetMethodID(
            dexPathListClass,
            "addDexPath",
            "(Ljava/lang/String;Ljava/io/File;)V"
        );
        
        if (addDexPathMethod != nullptr) {
            jstring jDexPath = jni->NewStringUTF(dex_path.c_str());
            jni->CallVoidMethod(pathList, addDexPathMethod, jDexPath, nullptr);
            jni->DeleteLocalRef(jDexPath);
            
            if (jni->ExceptionCheck()) {
                loge("[!] Exception while calling DexPathList.addDexPath");
                jni->ExceptionDescribe();
                jni->ExceptionClear();
            } else {
                logd("[*] Successfully added DEX to pathList");
            }
        } else {
            loge("[!] addDexPath method not found in DexPathList");
            jni->ExceptionClear();
        }
        
        jni->DeleteLocalRef(dexPathListClass);
        jni->DeleteLocalRef(pathList);
        jni->DeleteLocalRef(classLoaderClass);
        
        // 删除临时 DEX 文件
        if (remove(dex_path.c_str()) == 0) {
            logd("[*] Deleted temporary DEX file: %s", dex_path.c_str());
        } else {
            logw("[!] Failed to delete temporary DEX file: %s (errno: %d - %s)", 
                 dex_path.c_str(), errno, strerror(errno));
        }
        
        loaded = true;
        logd("[*] CrashHelper.dex loaded successfully");
        return true;
        
    } catch (const std::exception& e) {
        loge("[!] Exception while loading CrashHelper.dex: %s", e.what());
        return false;
    } catch (...) {
        loge("[!] Unknown exception while loading CrashHelper.dex");
        return false;
    }
}

// JVMTI 异常回调 - 捕获所有异常（包括除以0错误）并打印堆栈
static void JNICALL ExceptionCallback(
    jvmtiEnv* jvmti, JNIEnv* jni, jthread thread,
    jmethodID method, jlocation location, jobject exception,
    jmethodID catch_method, jlocation catch_location) {

    if (exception == nullptr) {
        return;
    }
    
    // 获取异常类
    jclass exceptionClass = jni->GetObjectClass(exception);
    if (exceptionClass == nullptr) {
        return;
    }
    
    // 获取异常类名
    jclass classClass = jni->FindClass("java/lang/Class");
    if (classClass == nullptr) {
        jni->ExceptionClear();
        jni->DeleteLocalRef(exceptionClass);
        return;
    }
    
    jmethodID getNameMethod = jni->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
    if (getNameMethod == nullptr) {
        jni->ExceptionClear();
        jni->DeleteLocalRef(classClass);
        jni->DeleteLocalRef(exceptionClass);
        return;
    }
    
    jstring classNameStr = (jstring)jni->CallObjectMethod(exceptionClass, getNameMethod);
    const char* className = nullptr;
    if (classNameStr != nullptr) {
        className = jni->GetStringUTFChars(classNameStr, nullptr);
    }
    
    // 获取异常消息
    jmethodID getMessageMethod = jni->GetMethodID(exceptionClass, "getMessage", "()Ljava/lang/String;");
    jstring messageStr = nullptr;
    const char* message = nullptr;
    if (getMessageMethod != nullptr) {
        messageStr = (jstring)jni->CallObjectMethod(exception, getMessageMethod);
        if (messageStr != nullptr) {
            message = jni->GetStringUTFChars(messageStr, nullptr);
        }
    }
    
    // 检查是否是除以0错误 (ArithmeticException)
    bool isDivideByZero = false;
    if (className != nullptr) {
        isDivideByZero = (strcmp(className, "java.lang.ArithmeticException") == 0);
    }
    
    if (isDivideByZero) {
        loge("[!] ========================================");
        loge("[!] EXCEPTION CAUGHT: %s", className ? className : "Unknown");
        if (message != nullptr) {
            loge("[!] Message: %s", message);
        }
        loge("[!] Location: method=%p, location=%lld", method, (long long)location);
        
        // 获取 Java 方法信息
        char* methodName = nullptr;
        char* methodSignature = nullptr;
        char* methodGeneric = nullptr;
        jclass declaringClass = nullptr;
        
        jvmtiError error = jvmti->GetMethodName(method, &methodName, &methodSignature, &methodGeneric);
        if (error == JVMTI_ERROR_NONE) {
            error = jvmti->GetMethodDeclaringClass(method, &declaringClass);
            if (error == JVMTI_ERROR_NONE && declaringClass != nullptr) {
                char* classSignature = nullptr;
                error = jvmti->GetClassSignature(declaringClass, &classSignature, nullptr);
                if (error == JVMTI_ERROR_NONE && classSignature != nullptr) {
                    loge("[!] Java Method: %s.%s%s", classSignature, methodName ? methodName : "?", 
                         methodSignature ? methodSignature : "");
                    jvmti->Deallocate((unsigned char*)classSignature);
                }
            }
            
            if (methodName != nullptr) {
                jvmti->Deallocate((unsigned char*)methodName);
            }
            if (methodSignature != nullptr) {
                jvmti->Deallocate((unsigned char*)methodSignature);
            }
            if (methodGeneric != nullptr) {
                jvmti->Deallocate((unsigned char*)methodGeneric);
            }
        }
        
        // 根据模式打印堆栈
        switch (g_stack_trace_mode) {
            case STACK_TRACE_NATIVE:
                PrintNativeBacktrace();
                break;
            case STACK_TRACE_JAVA:
                PrintJavaBacktrace(jvmti, thread);
                break;
            case STACK_TRACE_BOTH:
                PrintNativeBacktrace();
                loge("[!]");  // 空行分隔
                PrintJavaBacktrace(jvmti, thread);
                break;
            case STACK_TRACE_NULL:
                break;
        }
        
        loge("[!] ========================================");
    }
    
    // 清理
    if (className != nullptr && classNameStr != nullptr) {
        jni->ReleaseStringUTFChars(classNameStr, className);
    }
    if (message != nullptr && messageStr != nullptr) {
        jni->ReleaseStringUTFChars(messageStr, message);
    }
    if (classNameStr != nullptr) {
        jni->DeleteLocalRef(classNameStr);
    }
    if (messageStr != nullptr) {
        jni->DeleteLocalRef(messageStr);
    }
    jni->DeleteLocalRef(classClass);
    jni->DeleteLocalRef(exceptionClass);
    
    // 清除 Java 异常，防止异常继续传播
    if (jni->ExceptionCheck()) {
        logd("[*] Clearing Java exception after handling");
        jni->ExceptionClear();
    }

    if (isDivideByZero) {
        FindAndPrintMoveToExceptionHandlerArgs();
    }
}

// JVMTI ClassFileLoadHook 回调 - 反编译 DEX 字节码并插入 CrashHelper.triggerCrash() 调用
static void JNICALL ClassFileLoadHookCallback(
    jvmtiEnv* jvmti, JNIEnv* jni, jclass class_being_redefined, 
    jobject loader, const char* name, jobject protection_domain, 
    jint class_data_len, const unsigned char* class_data, 
    jint* new_class_data_len, unsigned char** new_class_data) {
    
    if (name == nullptr) {
        return;
    }
    
    // 过滤目标类：com/zxc/jtik/demo/TestActivity$1
    std::string className(name);
    if (className.find("com/zxc/jtik/demo/TestActivity$1") == std::string::npos) {
        return;
    }

    LoadCrashHelperDex(jni, loader);
    
    logd("[*] ========================================");
    logd("[*] ClassFileLoadHook: intercepted class %s (size: %d bytes)", name, class_data_len);
    logd("[*] ========================================");
    
    try {
        // 使用 Dexter slicer 读取 DEX 数据
        dex::Reader reader(class_data, class_data_len);
        
        // 转换类名为 JNI 格式 (com/zxc/jtik/demo/TestActivity$1 -> Lcom/zxc/jtik/demo/TestActivity$1;)
        std::string jni_class_name = "L" + className + ";";
        logd("[*] Looking for class: %s", jni_class_name.c_str());
        
        // 查找类索引
        auto class_index = reader.FindClassIndex(jni_class_name.c_str());
        if (class_index == dex::kNoIndex) {
            loge("[!] Class not found in DEX: %s", jni_class_name.c_str());
            return;
        }
        
        logd("[*] Found class at index: %u", class_index);
        
        // 创建类的 IR
        reader.CreateClassIr(class_index);
        auto dex_ir = reader.GetIr();
        
        if (dex_ir == nullptr) {
            loge("[!] Failed to create DEX IR for class %s", name);
            return;
        }
        
        logd("[*] Successfully parsed DEX for class %s", name);
        logd("[*] DEX IR contains %zu classes", dex_ir->classes.size());
        
        if (dex_ir->classes.empty()) {
            loge("[!] No classes found in DEX IR");
            return;
        }
        
        logd("[*] ========================================");
        logd("[*] Original class structure:");
        logd("[*] ========================================");
        
        // 遍历所有类并打印详细信息
        for (auto& ir_class : dex_ir->classes) {
            PrintClassMethods(ir_class.get(), dex_ir);
        }
        
        logd("[*] ========================================");
        logd("[*] Creating CrashHelper method reference and inserting calls...");
        logd("[*] ========================================");
        
        // 创建 CrashHelper.triggerCrash() 方法引用（只创建一次）
        auto crash_method_decl = CreateCrashHelperMethodRef(dex_ir);
        if (crash_method_decl == nullptr) {
            loge("[!] Failed to create CrashHelper method reference");
            return;
        }
        
        // 为所有类的方法插入 CrashHelper.triggerCrash() 调用
        for (auto& ir_class : dex_ir->classes) {
            logd("[*] Processing class: %s", ir_class->type->descriptor->c_str());
            
            // 为所有直接方法插入 CrashHelper.triggerCrash() 调用
            for (auto& method : ir_class->direct_methods) {
                try {
                    InsertCrashHelperCallBeforeEachInstruction(method, dex_ir, crash_method_decl);
                } catch (const std::exception& e) {
                    loge("[!] Failed to process direct method %s: %s", 
                         method->decl->name->c_str(), e.what());
                } catch (...) {
                    loge("[!] Unknown error processing direct method %s", 
                         method->decl->name->c_str());
                }
            }
            
            // 为所有虚方法插入 CrashHelper.triggerCrash() 调用
            for (auto& method : ir_class->virtual_methods) {
                try {
                    InsertCrashHelperCallBeforeEachInstruction(method, dex_ir, crash_method_decl);
                } catch (const std::exception& e) {
                    loge("[!] Failed to process virtual method %s: %s", 
                         method->decl->name->c_str(), e.what());
                } catch (...) {
                    loge("[!] Unknown error processing virtual method %s", 
                         method->decl->name->c_str());
                }
            }
        }
        
        // 写回修改后的 DEX
        logd("[*] Writing modified DEX...");
        dex::Writer writer(dex_ir);
        
        JvmtiAllocator allocator(jvmti);
        size_t new_image_size = 0;
        dex::u1* new_image = writer.CreateImage(&allocator, &new_image_size);
        
        if (new_image == nullptr) {
            loge("[!] Failed to create new DEX image");
            return;
        }
        
        logd("[*] New modified class DEX size: %zu bytes (original full DEX: %d bytes)", new_image_size, class_data_len);
        logd("[*] Note: Modified DEX contains only the target class, not the full DEX");
        
        // 保存 DEX 文件用于调试
        #ifdef DEBUG_DEX_FILE
        // 获取应用缓存目录
        std::string cache_dir = GetAppCacheDir(jni);
        
        std::vector<std::string> possible_paths;

        if (!cache_dir.empty()) {
            possible_paths.push_back(cache_dir + "/modified_class.dex");
        }
        
        bool saved = false;
        for (const auto& debug_path : possible_paths) {
            FILE* debug_file = fopen(debug_path.c_str(), "wb");
            if (debug_file != nullptr) {
                size_t written = fwrite(new_image, 1, new_image_size, debug_file);
                fclose(debug_file);
                logd("[*] Saved modified DEX to: %s (%zu bytes written)", debug_path.c_str(), written);
                saved = true;
                break;
            }
        }
        
        if (!saved) {
            loge("[!] Failed to save debug DEX file to any path (errno: %d - %s)", errno, strerror(errno));
            loge("[!] Tried paths:");
            for (const auto& path : possible_paths) {
                loge("[!]   - %s", path.c_str());
            }
        }
        #endif
        
        // 返回修改后的类数据
        *new_class_data_len = new_image_size;
        *new_class_data = new_image;
        
        logd("[*] DEX modification completed for class %s", name);
        logd("[*] ========================================");
        
    } catch (const std::exception& e) {
        loge("[!] Exception while processing DEX for class %s: %s", name, e.what());
    } catch (...) {
        loge("[!] Unknown exception while processing DEX for class %s", name);
    }
}

// 初始化 JVMTI
bool InitJvmti(JavaVM *vm) {
    if (vm == nullptr) {
        loge("[!] InitJvmti: vm is nullptr");
        return false;
    }
    
    // 创建 JVMTI 环境
    g_jvmti_env = CreateJvmtiEnv(vm);
    if (g_jvmti_env == nullptr) {
        loge("[!] Failed to create JVMTI environment");
        return false;
    }
    
    logd("[*] JVMTI environment created: %p", g_jvmti_env);
    
    // 设置能力
    int capResult = SetJvmtiCapabilities(g_jvmti_env);
    if (capResult != JVMTI_ERROR_NONE) {
        loge("[!] Failed to set JVMTI capabilities");
        return false;
    }
    
    // 设置事件回调
    jvmtiEventCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = &ClassFileLoadHookCallback;
    callbacks.Exception = &ExceptionCallback;
    
    jvmtiError error = g_jvmti_env->SetEventCallbacks(&callbacks, sizeof(callbacks));
    if (error != JVMTI_ERROR_NONE) {
        loge("[!] Failed to set JVMTI event callbacks, error: %d", error);
        return false;
    }
    
    // 启用 ClassFileLoadHook 事件
    error = g_jvmti_env->SetEventNotificationMode(
        JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
    if (error != JVMTI_ERROR_NONE) {
        loge("[!] Failed to enable ClassFileLoadHook event, error: %d", error);
        return false;
    }
    
    // 启用 Exception 事件
    error = g_jvmti_env->SetEventNotificationMode(
        JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, nullptr);
    if (error != JVMTI_ERROR_NONE) {
        logw("[!] Failed to enable Exception event, error: %d (may not be supported)", error);
        // 不返回 false，因为异常事件可能不被支持
    } else {
        logd("[*] Exception event enabled successfully");
    }
    
    logd("[*] JVMTI initialized successfully");
    return true;
}

// ==================== JVMTI Agent 生命周期函数 ====================

/**
 * Agent_OnLoad - 在 VM 初始化期间调用（通过 -agentlib/-agentpath 参数）
 * 这是最早的加载时机，可以在 VM 完全启动前进行初始化
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    logd("[*] Agent_OnLoad called with options: %s", options ? options : "none");
    
    if (InitJvmti(vm)) {
        logd("[*] Agent_OnLoad: JVMTI initialized successfully");
        return JNI_OK;
    } else {
        loge("[!] Agent_OnLoad: JVMTI initialization failed");
        return JNI_ERR;
    }
}

/**
 * Agent_OnAttach - 在运行时动态附加 Agent 时调用
 * 通过 VirtualMachine.attach() 或类似机制附加时触发
 */
JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    if (g_jvmti_env != nullptr) {
        logd("[*] Agent_OnAttach: JVMTI already initialized");
        return JNI_OK;
    }
    
    if (InitJvmti(vm)) {
        logd("[*] Agent_OnAttach: JVMTI initialized successfully");
        return JNI_OK;
    } else {
        loge("[!] Agent_OnAttach: JVMTI initialization failed");
        return JNI_ERR;
    }
}

/**
 * Agent_OnUnload - 在 Agent 卸载时调用
 * 用于清理资源
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    logd("[*] Agent_OnUnload called");
    
    if (g_jvmti_env != nullptr) {
        // 禁用所有事件
        g_jvmti_env->SetEventNotificationMode(
            JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, nullptr);
        g_jvmti_env->SetEventNotificationMode(
            JVMTI_DISABLE, JVMTI_EVENT_EXCEPTION, nullptr);
        
        logd("[*] JVMTI environment cleaned up");
        g_jvmti_env = nullptr;
    }
    
    logd("[*] Agent_OnUnload completed");
}
