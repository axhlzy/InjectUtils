#include "bindings.h"
#include "jvmti_helper.h"
#include "main.h"
#include <string>
#include <vector>
#include <sstream>

/**
 * JVMTI Lua 绑定
 * 提供 JVMTI 能力的 Lua 接口
 */

// ==================== 线程附加辅助类 ====================

/**
 * RAII 类：自动附加/分离 JVM 线程
 * 确保 JVMTI 调用在附加的线程中执行
 */
class JvmThreadAttacher {
private:
    JavaVM* vm_;
    JNIEnv* env_;
    bool needDetach_;

public:
    JvmThreadAttacher() : vm_(g_jvm), env_(nullptr), needDetach_(false) {
        if (vm_ == nullptr) {
            return;
        }
        
        // 尝试获取当前线程的 JNIEnv
        jint result = vm_->GetEnv((void**)&env_, JNI_VERSION_1_6);
        
        if (result == JNI_EDETACHED) {
            // 线程未附加，需要附加
            result = vm_->AttachCurrentThread(&env_, nullptr);
            if (result == JNI_OK) {
                needDetach_ = true;
            } else {
                env_ = nullptr;
            }
        }
    }
    
    ~JvmThreadAttacher() {
        if (needDetach_ && vm_ != nullptr) {
            vm_->DetachCurrentThread();
        }
    }
    
    JNIEnv* getEnv() const { return env_; }
    bool isAttached() const { return env_ != nullptr; }
};

// ==================== 类信息获取 ====================

/**
 * 获取所有已加载的类
 * @return 类名列表
 */
std::vector<std::string> GetLoadedClasses() {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    if (!attacher.isAttached()) {
        console->error("[!] Failed to attach thread to JVM");
        return {};
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return {};
    }
    
    jint classCount = 0;
    jclass* classes = nullptr;
    jvmtiError error = jvmti->GetLoadedClasses(&classCount, &classes);
    
    if (error != JVMTI_ERROR_NONE) {
        console->error("[!] GetLoadedClasses failed: {}", error);
        return {};
    }
    
    std::vector<std::string> result;
    for (jint i = 0; i < classCount; i++) {
        char* signature = nullptr;
        error = jvmti->GetClassSignature(classes[i], &signature, nullptr);
        if (error == JVMTI_ERROR_NONE && signature != nullptr) {
            result.push_back(signature);
            jvmti->Deallocate((unsigned char*)signature);
        }
    }
    
    jvmti->Deallocate((unsigned char*)classes);
    console->info("[*] Found {} loaded classes", classCount);

    for (jint i = 0; i < result.size(); i++) {
        console->info("[*] Loaded class: {}", result[i]);
    }

    return result;
}

/**
 * 获取类的签名
 * @param className 类名（如 "java/lang/String"）
 * @return 类签名
 */
std::string GetClassSignature(const char* className) {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    JNIEnv* env = attacher.getEnv();
    if (!attacher.isAttached() || env == nullptr) {
        console->error("[!] Failed to attach thread to JVM");
        return "";
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return "";
    }
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        console->error("[!] Class not found: {}", className);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return "";
    }
    
    char* signature = nullptr;
    jvmtiError error = jvmti->GetClassSignature(clazz, &signature, nullptr);
    
    std::string result;
    if (error == JVMTI_ERROR_NONE && signature != nullptr) {
        result = signature;
        jvmti->Deallocate((unsigned char*)signature);
    } else {
        console->error("[!] GetClassSignature failed: {}", error);
    }
    
    env->DeleteLocalRef(clazz);
    return result;
}

/**
 * 获取类的方法列表
 * @param className 类名
 * @return 方法名列表
 */
std::vector<std::string> GetClassMethods(const char* className) {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    JNIEnv* env = attacher.getEnv();
    if (!attacher.isAttached() || env == nullptr) {
        console->error("[!] Failed to attach thread to JVM");
        return {};
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return {};
    }
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        console->error("[!] Class not found: {}", className);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return {};
    }
    
    jint methodCount = 0;
    jmethodID* methods = nullptr;
    jvmtiError error = jvmti->GetClassMethods(clazz, &methodCount, &methods);
    
    std::vector<std::string> result;
    if (error == JVMTI_ERROR_NONE) {
        for (jint i = 0; i < methodCount; i++) {
            char* name = nullptr;
            char* signature = nullptr;
            error = jvmti->GetMethodName(methods[i], &name, &signature, nullptr);
            
            if (error == JVMTI_ERROR_NONE && name != nullptr) {
                std::string methodInfo = name;
                if (signature != nullptr) {
                    methodInfo += signature;
                    jvmti->Deallocate((unsigned char*)signature);
                }
                result.push_back(methodInfo);
                jvmti->Deallocate((unsigned char*)name);
            }
        }
        jvmti->Deallocate((unsigned char*)methods);
        console->info("[*] Found {} methods in class {}", methodCount, className);
    } else {
        console->error("[!] GetClassMethods failed: {}", error);
    }
    
    env->DeleteLocalRef(clazz);
    return result;
}

/**
 * 获取类的字段列表
 * @param className 类名
 * @return 字段名列表
 */
std::vector<std::string> GetClassFields(const char* className) {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    JNIEnv* env = attacher.getEnv();
    if (!attacher.isAttached() || env == nullptr) {
        console->error("[!] Failed to attach thread to JVM");
        return {};
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return {};
    }
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        console->error("[!] Class not found: {}", className);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return {};
    }
    
    jint fieldCount = 0;
    jfieldID* fields = nullptr;
    jvmtiError error = jvmti->GetClassFields(clazz, &fieldCount, &fields);
    
    std::vector<std::string> result;
    if (error == JVMTI_ERROR_NONE) {
        for (jint i = 0; i < fieldCount; i++) {
            char* name = nullptr;
            char* signature = nullptr;
            error = jvmti->GetFieldName(clazz, fields[i], &name, &signature, nullptr);
            
            if (error == JVMTI_ERROR_NONE && name != nullptr) {
                std::string fieldInfo = name;
                if (signature != nullptr) {
                    fieldInfo += " : ";
                    fieldInfo += signature;
                    jvmti->Deallocate((unsigned char*)signature);
                }
                result.push_back(fieldInfo);
                jvmti->Deallocate((unsigned char*)name);
            }
        }
        jvmti->Deallocate((unsigned char*)fields);
        console->info("[*] Found {} fields in class {}", fieldCount, className);
    } else {
        console->error("[!] GetClassFields failed: {}", error);
    }
    
    env->DeleteLocalRef(clazz);
    return result;
}

// ==================== 类加载器信息 ====================

/**
 * 获取类的类加载器
 * @param className 类名
 * @return 类加载器信息
 */
std::string GetClassLoader(const char* className) {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    JNIEnv* env = attacher.getEnv();
    if (!attacher.isAttached() || env == nullptr) {
        console->error("[!] Failed to attach thread to JVM");
        return "";
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return "";
    }
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        console->error("[!] Class not found: {}", className);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return "";
    }
    
    jobject classLoader = nullptr;
    jvmtiError error = jvmti->GetClassLoader(clazz, &classLoader);
    
    std::string result;
    if (error == JVMTI_ERROR_NONE) {
        if (classLoader == nullptr) {
            result = "Bootstrap ClassLoader";
        } else {
            jclass loaderClass = env->GetObjectClass(classLoader);
            char* signature = nullptr;
            jvmti->GetClassSignature(loaderClass, &signature, nullptr);
            if (signature != nullptr) {
                result = signature;
                jvmti->Deallocate((unsigned char*)signature);
            }
            env->DeleteLocalRef(loaderClass);
            env->DeleteLocalRef(classLoader);
        }
    } else {
        console->error("[!] GetClassLoader failed: {}", error);
    }
    
    env->DeleteLocalRef(clazz);
    return result;
}

// ==================== 线程信息 ====================

/**
 * 获取所有线程
 * @return 线程数量
 */
int GetAllThreads() {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    if (!attacher.isAttached()) {
        console->error("[!] Failed to attach thread to JVM");
        return 0;
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return 0;
    }
    
    jint threadCount = 0;
    jthread* threads = nullptr;
    jvmtiError error = jvmti->GetAllThreads(&threadCount, &threads);
    
    if (error != JVMTI_ERROR_NONE) {
        console->error("[!] GetAllThreads failed: {}", error);
        return 0;
    }
    
    console->info("[*] Found {} threads", threadCount);
    
    // 打印线程信息
    for (jint i = 0; i < threadCount; i++) {
        jvmtiThreadInfo threadInfo;
        error = jvmti->GetThreadInfo(threads[i], &threadInfo);
        if (error == JVMTI_ERROR_NONE) {
            console->info("  [{}] {}", i, threadInfo.name ? threadInfo.name : "<unnamed>");
            if (threadInfo.name != nullptr) {
                jvmti->Deallocate((unsigned char*)threadInfo.name);
            }
        }
    }
    
    jvmti->Deallocate((unsigned char*)threads);
    return threadCount;
}

// ==================== 堆信息 ====================

/**
 * 获取对象大小
 * @param className 类名
 * @return 对象大小（字节）
 */
long GetObjectSize(const char* className) {
    // 确保当前线程已附加到 JVM
    JvmThreadAttacher attacher;
    JNIEnv* env = attacher.getEnv();
    if (!attacher.isAttached() || env == nullptr) {
        console->error("[!] Failed to attach thread to JVM");
        return 0;
    }
    
    jvmtiEnv* jvmti = GetGlobalJvmtiEnv();
    if (jvmti == nullptr) {
        console->error("[!] JVMTI not initialized");
        return 0;
    }
    
    jclass clazz = env->FindClass(className);
    if (clazz == nullptr) {
        console->error("[!] Class not found: {}", className);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        return 0;
    }
    
    jlong size = 0;
    jvmtiError error = jvmti->GetObjectSize(clazz, &size);
    
    if (error != JVMTI_ERROR_NONE) {
        console->error("[!] GetObjectSize failed: {}", error);
        size = 0;
    } else {
        console->info("[*] Object size: {} bytes", size);
    }
    
    env->DeleteLocalRef(clazz);
    return (long)size;
}

// ==================== 工具函数 ====================

/**
 * 检查 JVMTI 是否已初始化
 */
bool IsJvmtiInitialized() {
    jvmtiEnv* env = GetGlobalJvmtiEnv();
    bool initialized = (env != nullptr);
    console->info("[*] JVMTI initialized: {} (env = {:p})", initialized ? "yes" : "no", (void*)env);
    return initialized;
}

/**
 * 搜索类（支持模糊匹配）
 * @param pattern 搜索模式
 * @return 匹配的类名列表
 */
std::vector<std::string> SearchClasses(const char* pattern) {
    auto allClasses = GetLoadedClasses();
    std::vector<std::string> result;
    
    std::string patternStr(pattern);
    for (const auto& className : allClasses) {
        if (className.find(patternStr) != std::string::npos) {
            result.push_back(className);
        }
    }
    
    console->info("[*] Found {} classes matching '{}'", result.size(), pattern);
    return result;
}

// ==================== Lua 绑定 ====================

BINDFUNC(jvmti) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("jvmti")
        
        // 类信息
        .addFunction("getLoadedClasses", GetLoadedClasses)
        .addFunction("getClassSignature", GetClassSignature)
        .addFunction("getClassMethods", GetClassMethods)
        .addFunction("getClassFields", GetClassFields)
        .addFunction("getClassLoader", GetClassLoader)
        .addFunction("searchClasses", SearchClasses)
        
        // 线程信息
        .addFunction("getAllThreads", GetAllThreads)
        
        // 堆信息
        .addFunction("getObjectSize", GetObjectSize)
        
        // 工具函数
        .addFunction("isInitialized", IsJvmtiInitialized)
        
        .endNamespace();
}
