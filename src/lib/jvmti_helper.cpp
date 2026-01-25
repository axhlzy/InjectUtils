#include "jvmti_helper.h"
#include "log.h"
#include "xdl.h"
#include <dlfcn.h>
#include <cstring>

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

    struct IterateData {
        const char* target_so;
        void* target_handle;
        int found_count;
    };
    
    IterateData data = {GetCurrentSoPath().append("1").c_str(), nullptr, 0};
    
    xdl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        IterateData* iter_data = static_cast<IterateData*>(data);

        if (info->dlpi_name != nullptr && strstr(info->dlpi_name, iter_data->target_so) != nullptr) {
            iter_data->found_count++;
            
            // 跳过第一个（可执行文件），取第二个（.so 文件）
            if (iter_data->found_count == 1) {
                iter_data->target_handle = xdl_open(info->dlpi_name, XDL_DEFAULT);
                if (iter_data->target_handle != nullptr) {
                    logd("[*] Found second at: %s", info->dlpi_name);
                    return 1; // 停止迭代
                }
            } else {
                logd("[*] Skipping first uinjector at: %s", info->dlpi_name);
            }
        }
        return 0;
    }, &data, XDL_DEFAULT);
    
    if (data.target_handle != nullptr) {
        // 从 .so 中获取 g_jvmti_env 符号
        g_jvmti_env_from_so = static_cast<jvmtiEnv**>(
            xdl_sym(data.target_handle, "g_jvmti_env", nullptr));
        xdl_close(data.target_handle);
        
        if (g_jvmti_env_from_so != nullptr) {
            logd("[*] GetGlobalJvmtiEnv: loaded g_jvmti_env from second uinjector: %p", 
                 *g_jvmti_env_from_so);
            return *g_jvmti_env_from_so;
        } else {
            loge("[!] GetGlobalJvmtiEnv: failed to find g_jvmti_env symbol in second uinjector");
        }
    } else {
        loge("[!] GetGlobalJvmtiEnv: failed to find second uinjector (found %d instances)", data.found_count);
    }

    return g_jvmti_env;
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

    // agentPath = std::string(agentPath).c_str();
    agentPath = (std::string(agentPath).append("1")).c_str();

    // 查找 dalvik.system.VMDebug 类
    jclass vmDebugClass = env->FindClass("dalvik/system/VMDebug");
    if (vmDebugClass == nullptr) {
        loge("[!] Failed to find dalvik.system.VMDebug class");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
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
        return false;
    }
    
    // 创建 agent 路径字符串
    jstring agentPathStr = env->NewStringUTF(agentPath);
    if (agentPathStr == nullptr) {
        loge("[!] Failed to create agent path string");
        env->DeleteLocalRef(vmDebugClass);
        return false;
    }
    
    logd("[*] VMDebug | cls:%p | mid:%p", vmDebugClass, attachAgentMethod);
    logd("[*] Attaching JVMTI agent: %s with classLoader: %p", agentPath, classLoader);
    
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
    logd("[*] GetPotentialCapabilities: retransform=%d, retransform_any=%d, native_prefix=%d, error=%d", 
         caps.can_retransform_classes, caps.can_retransform_any_class, 
         caps.can_set_native_method_prefix, error);
    
    jvmtiCapabilities newCaps = {0};
    newCaps.can_retransform_classes = 1;
    if (caps.can_set_native_method_prefix) {
        newCaps.can_set_native_method_prefix = 1;
    }
    
    error = jvmti->AddCapabilities(&newCaps);
    if (error != JVMTI_ERROR_NONE) {
        loge("[!] Failed to add JVMTI capabilities, error: %d", error);
        return error;
    }
    
    logd("[*] JVMTI capabilities added successfully");
    return JVMTI_ERROR_NONE;
}

// JVMTI ClassFileLoadHook 回调（预留，可以后续实现）
static void JNICALL ClassFileLoadHookCallback(
    jvmtiEnv* jvmti, JNIEnv* jni, jclass class_being_redefined, 
    jobject loader, const char* name, jobject protection_domain, 
    jint class_data_len, const unsigned char* class_data, 
    jint* new_class_data_len, unsigned char** new_class_data) {
    
    // 这里可以实现类文件转换逻辑
    // 目前只是记录日志
    logd("[*] ClassFileLoadHook: %s", name ? name : "unknown");
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
    logd("[*] Agent_OnAttach called with options: %s", options ? options : "none");
    
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
        
        logd("[*] JVMTI environment cleaned up");
        g_jvmti_env = nullptr;
    }
    
    logd("[*] Agent_OnUnload completed");
}
