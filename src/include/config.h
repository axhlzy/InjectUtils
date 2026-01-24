#pragma once

#include <cstddef>  // for size_t

namespace Config {
    // 管道和通信配置
    constexpr const char* PIPE_NAME = "/data/local/tmp/uinjector_pipe";
    constexpr const char* LOG_TAG = "UInjector";
    constexpr int SOCKET_PORT = 8024;
    
    // 重启限制
    constexpr int MAX_RESTART_TIMES = 3;
    
    // 虚拟栈大小
    constexpr size_t VIRTUAL_STACK_SIZE = 0x1000 * 10000;
    
    // 路径配置
    constexpr const char* LIBART_SO = "libart.so";
    constexpr const char* LIBIL2CPP_SO = "libil2cpp.so";
}
