#include "bindings.h"
#include "jvmti_helper.h"
#include "main.h"
#include <string>
#include <vector>

/**
 * JVMTI 工具函数 Lua 绑定
 * 提供类重转换、Agent 附加等高级功能
 */

// ==================== 线程附加辅助类 ====================

/**
 * RAII 类：自动附加/分离 JVM 线程
 */
class JvmThreadAttacherTools {
private:
    JavaVM* vm_;
    JNIEnv* env_;
    bool needDetach_;

public:
    JvmThreadAttacherTools() : vm_(g_jvm), env_(nullptr), needDetach_(false) {
        if (vm_ == nullptr) {
            return;
        }
        
        jint result = vm_->GetEnv((void**)&env_, JNI_VERSION_1_6);
        
        if (result == JNI_EDETACHED) {
            result = vm_->AttachCurrentThread(&env_, nullptr);
            if (result == JNI_OK) {
                needDetach_ = true;
            } else {
                env_ = nullptr;
            }
        }
    }
    
    ~JvmThreadAttacherTools() {
        if (needDetach_ && vm_ != nullptr) {
            vm_->DetachCurrentThread();
        }
    }
    
    JNIEnv* getEnv() const { return env_; }
    bool isAttached() const { return env_ != nullptr; }
};

// ==================== 类重转换函数 ====================

/**
 * 重转换已加载的类，使其重新触发 ClassFileLoadHook
 * @param className 类名（支持 com.example.MyClass 或 com/example/MyClass 格式）
 * @return 成功返回 true
 */
bool LuaRetransformClass(const char* className) {
    if (className == nullptr) {
        console->error("[!] retransformClass: className is null");
        return false;
    }
    
    JvmThreadAttacherTools attacher;
    if (!attacher.isAttached()) {
        console->error("[!] retransformClass: failed to attach thread to JVM");
        return false;
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] retransformClass: JVMTI not initialized");
        return false;
    }
    
    console->info("[*] Retransforming class: {}", className);
    bool result = RetransformLoadedClass(attacher.getEnv(), jvmti, className);
    
    if (result) {
        console->info("[*] Successfully triggered retransform for: {}", className);
    } else {
        console->error("[!] Failed to retransform class: {}", className);
    }
    
    return result;
}

/**
 * 批量重转换已加载的类
 * @param classNames Lua table 包含类名列表
 * @return 成功重转换的类数量
 */
int LuaRetransformClasses(luabridge::LuaRef classNamesTable) {
    if (!classNamesTable.isTable()) {
        console->error("[!] retransformClasses: parameter must be a table");
        return 0;
    }
    
    JvmThreadAttacherTools attacher;
    if (!attacher.isAttached()) {
        console->error("[!] retransformClasses: failed to attach thread to JVM");
        return 0;
    }
    
    // 从 Lua table 提取类名
    std::vector<std::string> classNamesStorage;
    std::vector<const char*> classNames;
    
    int len = classNamesTable.length();
    classNamesStorage.reserve(len);
    classNames.reserve(len);
    
    for (int i = 1; i <= len; i++) {
        luabridge::LuaRef item = classNamesTable[i];
        if (item.isString()) {
            auto result = item.cast<std::string>();
            if (result) {
                classNamesStorage.push_back(result.value());
                classNames.push_back(classNamesStorage.back().c_str());
            }
        }
    }
    
    if (classNames.empty()) {
        console->error("[!] retransformClasses: no valid class names provided");
        return 0;
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] retransformClasses: JVMTI not initialized");
        return 0;
    }
    
    console->info("[*] Retransforming {} classes...", classNames.size());
    int count = RetransformLoadedClasses(attacher.getEnv(), jvmti, 
                                          classNames.data(), 
                                          static_cast<int>(classNames.size()));
    
    console->info("[*] Successfully retransformed {} classes", count);
    return count;
}

// ==================== Agent 附加函数 ====================

/**
 * 动态附加 JVMTI Agent
 * @param agentPath Agent 文件路径
 * @return 成功返回 true
 */
bool LuaAttachAgent(const char* agentPath) {
    if (agentPath == nullptr) {
        console->error("[!] attachAgent: agentPath is null");
        return false;
    }
    
    JvmThreadAttacherTools attacher;
    if (!attacher.isAttached()) {
        console->error("[!] attachAgent: failed to attach thread to JVM");
        return false;
    }
    
    console->info("[*] Attaching JVMTI agent: {}", agentPath);
    bool result = AttachJvmtiAgent(attacher.getEnv(), agentPath, g_classLoader);
    
    if (result) {
        console->info("[*] Agent attached successfully");
    } else {
        console->error("[!] Failed to attach agent");
    }
    
    return result;
}

/**
 * 附加当前 SO 作为 JVMTI Agent
 * @return 成功返回 true
 */
bool LuaAttachSelfAsAgent() {
    JvmThreadAttacherTools attacher;
    if (!attacher.isAttached()) {
        console->error("[!] attachSelfAsAgent: failed to attach thread to JVM");
        return false;
    }
    
    std::string selfPath = GetCurrentSoPath();
    if (selfPath.empty()) {
        console->error("[!] attachSelfAsAgent: failed to get current SO path");
        return false;
    }
    
    console->info("[*] Attaching self as JVMTI agent: {}", selfPath);
    bool result = AttachJvmtiAgent(attacher.getEnv(), selfPath.c_str(), g_classLoader);
    
    if (result) {
        console->info("[*] Self attached as agent successfully");
    } else {
        console->error("[!] Failed to attach self as agent");
    }
    
    return result;
}

// ==================== 调试状态控制 ====================

/**
 * 设置调试状态
 * @param allowDebug true 允许调试，false 禁止调试
 * @return 成功返回 true
 */
bool LuaSetDebuggable(bool allowDebug) {
    console->info("[*] Setting debuggable state to: {}", allowDebug ? "true" : "false");
    bool result = SetDebuggableRelease(allowDebug);
    
    if (result) {
        console->info("[*] Debuggable state set successfully");
    } else {
        console->error("[!] Failed to set debuggable state");
    }
    
    return result;
}

// ==================== 堆栈打印模式 ====================

/**
 * 设置堆栈打印模式
 * @param mode 0=Native, 1=Java, 2=Both, 3=None
 */
void LuaSetStackTraceMode(int mode) {
    StackTraceMode traceMode;
    const char* modeName;
    
    switch (mode) {
        case 0:
            traceMode = STACK_TRACE_NATIVE;
            modeName = "NATIVE";
            break;
        case 1:
            traceMode = STACK_TRACE_JAVA;
            modeName = "JAVA";
            break;
        case 2:
            traceMode = STACK_TRACE_BOTH;
            modeName = "BOTH";
            break;
        case 3:
        default:
            traceMode = STACK_TRACE_NULL;
            modeName = "NONE";
            break;
    }
    
    SetStackTraceMode(traceMode);
    console->info("[*] Stack trace mode set to: {}", modeName);
}

/**
 * 获取当前堆栈打印模式
 * @return 0=Native, 1=Java, 2=Both, 3=None
 */
int LuaGetStackTraceMode() {
    return static_cast<int>(GetStackTraceMode());
}

// ==================== JVMTI 状态查询 ====================

/**
 * 获取 JVMTI 环境指针（用于调试）
 * @return JVMTI 环境指针地址
 */
uintptr_t LuaGetJvmtiEnvPtr() {
    jvmtiEnv* env = GetGlobalJvmtiEnv();
    uintptr_t ptr = reinterpret_cast<uintptr_t>(env);
    console->info("[*] JVMTI env pointer: 0x{:x}", ptr);
    return ptr;
}

/**
 * 获取当前 SO 路径
 * @return SO 文件路径
 */
std::string LuaGetCurrentSoPath() {
    std::string path = GetCurrentSoPath();
    console->info("[*] Current SO path: {}", path);
    return path;
}

// ==================== Lua 绑定 ====================

BINDFUNC(jvmti_tools) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("jvmti")
        
        .addFunction("retransformClass", LuaRetransformClass)
        .addFunction("retransformClasses", LuaRetransformClasses)
        
        .addFunction("attachAgent", LuaAttachAgent)
        .addFunction("attachSelfAsAgent", LuaAttachSelfAsAgent)
        
        .addFunction("setDebuggable", LuaSetDebuggable)
        
        .addFunction("setStackTraceMode", LuaSetStackTraceMode)
        .addFunction("getStackTraceMode", LuaGetStackTraceMode)
        
        .addFunction("getJvmtiEnvPtr", LuaGetJvmtiEnvPtr)
        .addFunction("getCurrentSoPath", LuaGetCurrentSoPath)
        
        .endNamespace();
}
