#ifndef JVMTI_HELPER_H
#define JVMTI_HELPER_H

#include <jni.h>
#include "jvmti.h"
#include <string>

/**
 * JVMTI 辅助工具函数
 * 提供 JVMTI 初始化、Agent 附加等功能
 */

// 全局 JVMTI 环境变量（在 jvmti_helper.cpp 中定义）
extern jvmtiEnv* g_jvmti_env;

/**
 * 堆栈打印模式
 */
enum StackTraceMode {
    STACK_TRACE_NATIVE = 0,  // 打印 Native 堆栈
    STACK_TRACE_JAVA = 1,    // 打印 Java 堆栈
    STACK_TRACE_BOTH = 2,     // 同时打印两种堆栈
    STACK_TRACE_NULL = 3     // 同时打印两种堆栈
};

/**
 * 设置异常回调的堆栈打印模式
 * @param mode 堆栈打印模式
 */
void SetStackTraceMode(StackTraceMode mode);

/**
 * 获取当前的堆栈打印模式
 * @return 当前的堆栈打印模式
 */
StackTraceMode GetStackTraceMode();

/**
 * 获取全局 JVMTI 环境
 * @return jvmtiEnv 指针，如果未初始化则返回 nullptr
 */
jvmtiEnv* GetGlobalJvmtiEnv();

/**
 * 设置调试状态（允许或禁止 JDWP 调试）
 * @param allowDebug true 允许调试，false 禁止调试
 * @return 成功返回 true，失败返回 false
 */
bool SetDebuggableRelease(bool allowDebug);

/**
 * 获取当前 so 文件的路径
 * @return so 文件的完整路径
 */
std::string GetCurrentSoPath();

/**
 * 动态附加 JVMTI Agent
 * 使用 dalvik.system.VMDebug.attachAgent 方法
 * @param env JNI 环境指针
 * @param agentPath Agent 文件路径
 * @param classLoader ClassLoader 对象
 * @return 成功返回 true，失败返回 false
 */
bool AttachJvmtiAgent(JNIEnv* env, const char* agentPath, jobject classLoader);

/**
 * 创建 JVMTI 环境
 * @param vm JavaVM 指针
 * @return jvmtiEnv 指针，失败返回 nullptr
 */
jvmtiEnv* CreateJvmtiEnv(JavaVM *vm);

/**
 * 设置 JVMTI 所需的能力
 * @param jvmti jvmtiEnv 指针
 * @return JVMTI 错误码
 */
int SetJvmtiCapabilities(jvmtiEnv *jvmti);

/**
 * 初始化 JVMTI
 * 创建环境、设置能力、注册回调
 * @param vm JavaVM 指针
 * @return 成功返回 true，失败返回 false
 */
bool InitJvmti(JavaVM *vm);

/**
 * 重转换已加载的类，使其重新触发 ClassFileLoadHook 回调
 * 用于在 Agent attach 后 hook 已经加载的类
 * @param env JNI 环境指针
 * @param jvmti JVMTI 环境指针（如果为 nullptr，则使用全局 g_jvmti_env）
 * @param className 类名（支持 com.example.MyClass 或 com/example/MyClass 格式）
 * @return 成功返回 true，失败返回 false
 */
bool RetransformLoadedClass(JNIEnv* env, jvmtiEnv* jvmti, const char* className);

/**
 * 批量重转换已加载的类
 * @param env JNI 环境指针
 * @param jvmti JVMTI 环境指针（如果为 nullptr，则使用全局 g_jvmti_env）
 * @param classNames 类名数组
 * @param count 类名数量
 * @return 成功重转换的类数量
 */
int RetransformLoadedClasses(JNIEnv* env, jvmtiEnv* jvmti, const char** classNames, int count);

#endif // JVMTI_HELPER_H
