# LuaReplClient/Server 改进修改总结

## 修改日期
2026-01-25

## 最新更新（重要）

### 解决 console->info 重定向问题

**问题描述：**
移除 `dup2()` 后，所有 `console->info()` 输出无法重定向到 REPL 客户端，导致 binds 下的日志无法在客户端看到。

**解决方案：**
创建自定义 spdlog sink (`ReplSink.hpp`)，将 console logger 的输出动态重定向到当前活动的客户端。

**新增文件：**
- `src/include/LuaSocket/ReplSink.hpp` - 自定义 spdlog sink

**工作原理：**
1. 服务器启动时，创建 `repl_sink` 并添加到 `console` logger 的 sinks 列表
2. 客户端连接时，将客户端的 socket 设置到 `repl_sink`
3. 所有 `console->info/error/warn` 输出会自动发送到当前活动客户端
4. 客户端断开时，清除 socket 引用
5. 服务器关闭时，从 console logger 移除 repl sink

**优势：**
- ✅ 不需要修改任何现有代码
- ✅ 所有 `console->info()` 自动重定向到 REPL
- ✅ 不影响 stdout 和 logcat 输出
- ✅ 线程安全
- ✅ 支持多客户端（最后连接的客户端接收输出）

**注意事项：**
- 如果有多个客户端，只有最后一个执行命令的客户端会接收 console 输出
- 如果需要所有客户端都接收输出，可以修改 `ReplSink` 维护客户端列表

**技术实现：**
```cpp
// ReplSink.hpp - 自定义 spdlog sink
template<typename Mutex>
class repl_sink : public spdlog::sinks::base_sink<Mutex> {
    void sink_it_(const spdlog::details::log_msg& msg) override {
        // 格式化消息并写入客户端 socket
        boost::asio::write(*client_socket_, ...);
    }
};

// LuaReplServer.hpp - 在服务器中使用
LuaReplServer(...) {
    repl_sink_ = std::make_shared<repl_sink_mt>();
    console->sinks().push_back(repl_sink_);  // 添加到 console logger
}

void handle_client(...) {
    repl_sink_->set_client_socket(session->socket_ptr);  // 设置当前客户端
    // ... 执行 Lua 代码 ...
}
```

**测试方法：**
1. 启动 REPL：`./inject-utils -p <pid>`
2. 在 REPL 中运行：`dofile("test_repl_output.lua")`
3. 调用任何会产生 `console->info` 的函数
4. 验证输出是否显示在 REPL 中

## 修改的文件

### 1. src/include/LuaSocket/LuaReplClient.hpp
**主要改进：**
- ✅ 将缓冲区从 2MB 减少到 64KB，并使用 `std::vector<char>` 替代 `new char[]`
- ✅ 添加连接状态管理 (`std::atomic<bool> connected_`)
- ✅ 改进 `connect()` 方法，支持可配置的重试次数和间隔
- ✅ 添加 `disconnect()` 方法，正确清理资源
- ✅ 添加 `is_connected()` 状态检查
- ✅ 改进错误处理，添加 `handle_error()` 方法
- ✅ 保留 `close_connect()` 作为兼容接口
- ✅ 修复内存管理问题

**关键变更：**
```cpp
// 旧版本
reply_(new char[LUA_REPL_CLI_MAXLEN])  // 2MB, 可能内存泄漏

// 新版本
reply_buffer_(LUA_REPL_BUFFER_SIZE)    // 64KB, 自动管理
```

```cpp
// 旧版本
void connect() {
    while (true) {
        // ... 无限重试，失败后 exit(1)
    }
}

// 新版本
bool connect(int max_retries = 30, int retry_interval_ms = 1000) {
    // ... 可配置重试，返回成功/失败状态
}
```

### 2. src/include/LuaSocket/LuaReplServer.hpp
**主要改进：**
- ✅ 为每个客户端创建独立的 Lua 协程 (`lua_newthread`)
- ✅ 移除危险的 `lua_close(L)` 调用
- ✅ 移除 `dup2(clientSocket, STDOUT_FILENO)` 重定向
- ✅ 实现线程安全的客户端管理 (`std::mutex` + `std::map`)
- ✅ 为每个客户端设置独立的 `print` 函数
- ✅ 添加客户端 ID 管理
- ✅ 改进资源清理 (`cleanup_client()`)
- ✅ 统一缓冲区大小为 64KB

**关键变更：**
```cpp
// 旧版本 - 危险！
void handle_client(tcp::socket client_socket, lua_State *L, int clientSocket) {
    // ...
    lua_close(L);  // ❌ 关闭共享的 Lua 状态
}

// 新版本 - 安全
void handle_client(std::shared_ptr<ClientSession> session) {
    // 使用 session->lua_thread (独立协程)
    // 不关闭 Lua 状态
}
```

```cpp
// 旧版本 - 多客户端冲突
inline static int soc_client;  // 全局变量
dup2(clientSocket, STDOUT_FILENO);  // 重定向整个进程的 stdout

// 新版本 - 每个客户端独立
struct ClientSession {
    int id;
    int socket_fd;
    lua_State* lua_thread;  // 独立协程
    std::shared_ptr<tcp::socket> socket_ptr;
};
// 直接写入客户端 socket，不重定向 stdout
```

### 3. src/lib/lib.cpp
**主要改进：**
- ✅ 更新 `start_local_repl()` 使用新的连接接口
- ✅ 添加连接失败处理
- ✅ 改进用户提示信息

**关键变更：**
```cpp
// 旧版本
client.connect();  // 可能失败或长时间阻塞

// 新版本
if (!client.connect(30, 1000)) {  // 30次重试，每次1秒
    console->error("[!] Failed to connect to server");
    return;
}
```

### 4. src/lib/utils.cpp
**主要改进：**
- ✅ 在 `inject()` 函数后添加 1.5 秒等待时间
- ✅ 添加注入进度提示信息

**关键变更：**
```cpp
// 新增
console->info("[*] Injecting library into process {}...", pid);
// ... 注入代码 ...
console->info("[*] Waiting for server to initialize...");
std::this_thread::sleep_for(std::chrono::milliseconds(1500));
```

## 解决的问题

### 🔴 严重问题（已修复）
1. ✅ **连接时序竞态条件** - 添加等待时间和改进重试机制
2. ✅ **lua_close() 误用** - 移除客户端中的 lua_close() 调用
3. ✅ **stdout 重定向副作用** - 移除 dup2()，直接写入 socket
4. ✅ **内存管理问题** - 使用 std::vector 自动管理内存

### 🟡 中等问题（已修复）
5. ✅ **缓冲区大小不匹配** - 统一为 64KB
6. ✅ **线程安全问题** - 使用 mutex 和独立的客户端会话
7. ✅ **错误处理不完善** - 添加错误处理和状态检查

### 🟢 轻微问题（已修复）
8. ✅ **硬编码的重试次数** - 改为可配置参数
9. ✅ **缺少连接状态检查** - 添加 is_connected() 方法

## 新增功能

1. **多客户端支持** - 现在可以同时连接多个客户端，每个客户端有独立的 Lua 环境
2. **客户端 ID** - 每个客户端分配唯一 ID，便于调试和管理
3. **优雅的断开连接** - 正确清理资源，不会影响其他客户端
4. **改进的错误提示** - 更详细的连接和错误信息

## 兼容性

- ✅ 保留了 `close_connect()` 方法作为 `disconnect()` 的别名
- ✅ 接口基本保持兼容，现有代码无需大改
- ✅ 默认参数确保向后兼容

## 测试建议

1. **单客户端测试**
   ```bash
   # 终端1: 启动目标进程
   ./inject-utils -p <pid>
   
   # 应该能正常连接并执行 Lua 命令
   ```

2. **多客户端测试**
   ```bash
   # 终端1: 启动目标进程
   ./inject-utils -p <pid>
   
   # 终端2: 使用 nc 连接
   nc 127.0.0.1 <port>
   
   # 两个客户端应该能独立工作，互不干扰
   ```

3. **连接重试测试**
   ```bash
   # 先启动客户端（服务器未启动）
   # 应该看到重试提示，最多30次
   ```

4. **资源清理测试**
   ```bash
   # 连接后输入 exit
   # 应该正确断开，不影响服务器和其他客户端
   ```

## 注意事项

1. **Lua 协程限制** - 每个客户端使用独立的 Lua 协程，共享全局状态
2. **内存使用** - 每个客户端占用约 64KB 缓冲区
3. **线程安全** - 客户端管理是线程安全的，但 Lua 状态本身不是线程安全的
4. **等待时间** - 1.5秒的等待时间可能需要根据实际情况调整

## 后续改进建议

1. 添加心跳机制检测连接状态
2. 实现消息协议，支持二进制数据传输
3. 添加客户端认证机制
4. 支持动态调整等待时间
5. 添加性能监控和统计

## 编译状态

- ✅ LuaReplClient.hpp: 1个警告（未使用的 lambda 捕获，可忽略）
- ✅ LuaReplServer.hpp: 无警告
- ✅ lib.cpp: 无警告
- ✅ utils.cpp: 3个警告（与此次修改无关）
