#ifndef STACKTRACE_HELPER_H
#define STACKTRACE_HELPER_H

#include <jvmti.h>

/**
 * 打印 Native 堆栈回溯
 * 使用 libunwind 捕获堆栈，并使用 dladdr 解析符号
 * 自动 demangle C++ 符号名称
 */
void PrintNativeBacktrace();

/**
 * 打印 Java 堆栈回溯
 * 使用 JVMTI GetStackTrace 获取 Java 方法调用栈
 * 
 * @param jvmti JVMTI 环境指针
 * @param thread 目标线程
 */
void PrintJavaBacktrace(jvmtiEnv* jvmti, jthread thread);

/**
 * 查找并打印 MoveToExceptionHandler 函数的参数
 * 通过 unwind 堆栈查找 art::interpreter::MoveToExceptionHandler 函数帧
 * 并提取其参数（Thread*, ShadowFrame&, Instrumentation*）
 * 然后迭代 ShadowFrame 链表打印详细信息
 */
void FindAndPrintMoveToExceptionHandlerArgs();

#endif // STACKTRACE_HELPER_H
