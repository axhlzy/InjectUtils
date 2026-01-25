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

#endif // JVMTI_HELPER_H
