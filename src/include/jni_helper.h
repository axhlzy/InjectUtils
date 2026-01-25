#ifndef JNI_HELPER_H
#define JNI_HELPER_H

#include <jni.h>

/**
 * JNI 辅助工具函数
 * 提供常用的 JNI 操作封装
 */

/**
 * 获取当前应用的 Application 对象
 * @param env JNI 环境指针
 * @return Application 对象，失败返回 nullptr
 */
jobject getApplication(JNIEnv *env);

/**
 * 初始化全局 Application ClassLoader
 * 调用后可以使用 findClassWithAppLoader 查找应用类
 * @param env JNI 环境指针
 * @param application Application 对象
 */
void initAppClassLoader(JNIEnv *env, jobject application);

/**
 * 使用 Application ClassLoader 查找类
 * 支持查找应用类，而不仅限于系统类
 * @param env JNI 环境指针
 * @param className 类名，支持 "com/xxx/yyy" 或 "com.xxx.yyy" 格式
 * @return jclass 对象，失败返回 nullptr
 */
jclass findClassWithAppLoader(JNIEnv *env, const char *className);

/**
 * 清理 JNI 全局资源
 * 释放全局 ClassLoader 引用
 * @param env JNI 环境指针
 */
void cleanupJniResources(JNIEnv *env);

#endif // JNI_HELPER_H
