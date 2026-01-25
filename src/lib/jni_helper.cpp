#include "jni_helper.h"
#include "log.h"
#include "main.h"
#include <algorithm>
#include <string>

jobject getApplication(JNIEnv *env) {
    if (env == nullptr) {
        loge("[!] getApplication: env is nullptr");
        return nullptr;
    }

    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass == nullptr) {
        loge("[!] Failed to find ActivityThread class");
        return nullptr;
    }

    jmethodID currentApplicationMethod = env->GetStaticMethodID(
        activityThreadClass, "currentApplication", "()Landroid/app/Application;");
    if (currentApplicationMethod == nullptr) {
        loge("[!] Failed to find currentApplication method");
        env->DeleteLocalRef(activityThreadClass);
        return nullptr;
    }

    jobject application = env->CallStaticObjectMethod(
        activityThreadClass, currentApplicationMethod);
    
    env->DeleteLocalRef(activityThreadClass);

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return nullptr;
    }

    return application;
}

void initAppClassLoader(JNIEnv *env, jobject application) {
    if (env == nullptr || application == nullptr) {
        loge("[!] initAppClassLoader: invalid parameters");
        return;
    }

    jclass contextClass = env->FindClass("android/content/Context");
    if (contextClass == nullptr) {
        loge("[!] Failed to find Context class");
        return;
    }

    jmethodID getClassLoaderMethod = env->GetMethodID(
        contextClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (getClassLoaderMethod == nullptr) {
        loge("[!] Failed to find getClassLoader method");
        env->DeleteLocalRef(contextClass);
        return;
    }

    jobject classLoader = env->CallObjectMethod(application, getClassLoaderMethod);
    env->DeleteLocalRef(contextClass);

    if (classLoader == nullptr) {
        loge("[!] Failed to get ClassLoader from Application");
        return;
    }

    // 创建全局引用，避免被 GC 回收
    g_classLoader = env->NewGlobalRef(classLoader);
    env->DeleteLocalRef(classLoader);
    
    logd("[*] Application ClassLoader initialized: %p", g_classLoader);
}

jclass findClassWithAppLoader(JNIEnv *env, const char *className) {
    if (env == nullptr || className == nullptr) {
        loge("[!] findClassWithAppLoader: invalid parameters");
        return nullptr;
    }

    // 如果没有初始化 ClassLoader，回退到普通 FindClass
    if (g_classLoader == nullptr) {
        logd("[!] g_classLoader not initialized, using FindClass");
        return env->FindClass(className);
    }

    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    if (classLoaderClass == nullptr) {
        loge("[!] Failed to find ClassLoader class");
        return nullptr;
    }

    jmethodID loadClassMethod = env->GetMethodID(
        classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (loadClassMethod == nullptr) {
        loge("[!] Failed to find loadClass method");
        env->DeleteLocalRef(classLoaderClass);
        return nullptr;
    }

    // 将 com/xxx/yyy 转换为 com.xxx.yyy
    std::string javaClassName = className;
    std::replace(javaClassName.begin(), javaClassName.end(), '/', '.');

    jstring classNameStr = env->NewStringUTF(javaClassName.c_str());
    jclass result = (jclass)env->CallObjectMethod(
        g_classLoader, loadClassMethod, classNameStr);

    env->DeleteLocalRef(classNameStr);
    env->DeleteLocalRef(classLoaderClass);

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return nullptr;
    }

    return result;
}

void cleanupJniResources(JNIEnv *env) {
    if (env != nullptr && g_classLoader != nullptr) {
        env->DeleteGlobalRef(g_classLoader);
        g_classLoader = nullptr;
        logd("[*] JNI resources cleaned up");
    }
}
