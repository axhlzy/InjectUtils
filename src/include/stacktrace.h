#ifndef STACKTRACE_H
#define STACKTRACE_H

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <jvmti.h>

#include "QBDI/State.h"

using namespace std;
using namespace QBDI;

/**
 * 内存区域信息
 */
struct MemRegion {
    unsigned long start;
    unsigned long end;
    unsigned long offset;
    std::string path;
    std::string name;
};

/**
 * 读取 /proc/self/maps 获取内存映射信息
 */
void read_maps();

/**
 * 查找包含指定地址的内存区域
 */
const MemRegion* find_mem_region(uintptr_t addr);

/**
 * 获取地址信息（符号名、库名、偏移）
 */
std::string get_addr_info(unsigned long addr);

/**
 * 堆栈回溯（基于帧指针）
 */
std::vector<uintptr_t> stacktrace(rword pc, rword lr, rword fp, rword sp);

/**
 * Unwind 堆栈回溯（调试用）
 */
void UnwindBacktrace(const string &lastFunctionName = "...", bool printRegisters = false);

/**
 * 打印堆栈回溯
 */
void printBacktrace(vector<void *> backtraceArray);

/**
 * Dump 堆栈到日志
 */
void dumpBacktrace(void **buffer, size_t count);

// ==================== JVMTI 堆栈打印 ====================

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

#endif // STACKTRACE_H