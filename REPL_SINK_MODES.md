# REPL Sink 模式说明

## 两种输出模式

### 模式 1: 单客户端模式（默认）
**文件：** `ReplSink.hpp`

**特点：**
- console->info 输出只发送到最后一个执行命令的客户端
- 性能更好，网络开销小
- 适合单人调试场景

**使用场景：**
- 单个开发者调试
- 性能敏感的应用
- 不需要多人同时查看输出

**实现：**
```cpp
// LuaReplServer.hpp
#include "ReplSink.hpp"  // 使用单客户端模式

repl_sink_ = std::make_shared<repl_sink_mt>();
console->sinks().push_back(repl_sink_);

// 设置当前活动客户端
repl_sink_->set_client_socket(session->socket_ptr);
```

### 模式 2: 广播模式
**文件：** `ReplSinkBroadcast.hpp`

**特点：**
- console->info 输出广播到所有连接的客户端
- 所有客户端都能看到相同的输出
- 网络开销较大

**使用场景：**
- 多人协作调试
- 需要多个终端同时监控
- 教学演示

**实现：**
```cpp
// LuaReplServer.hpp
#include "ReplSinkBroadcast.hpp"  // 使用广播模式

repl_sink_ = std::make_shared<repl_broadcast_sink_mt>();
console->sinks().push_back(repl_sink_);

// 添加客户端
repl_sink_->add_client_socket(session->socket_ptr);

// 移除客户端
repl_sink_->remove_client_socket(session->socket_ptr);
```

## 如何切换模式

### 方法 1: 修改 LuaReplServer.hpp（编译时）

**切换到广播模式：**
```cpp
// src/include/LuaSocket/LuaReplServer.hpp

// 注释掉单客户端模式
// #include "ReplSink.hpp"

// 启用广播模式
#include "ReplSinkBroadcast.hpp"

class LuaReplServer {
    // ...
    
    // 修改类型定义
    // std::shared_ptr<repl_sink_mt> repl_sink_;  // 单客户端
    std::shared_ptr<repl_broadcast_sink_mt> repl_sink_;  // 广播
    
    // 修改初始化
    LuaReplServer(...) {
        // repl_sink_ = std::make_shared<repl_sink_mt>();  // 单客户端
        repl_sink_ = std::make_shared<repl_broadcast_sink_mt>();  // 广播
        console->sinks().push_back(repl_sink_);
    }
    
    // 修改客户端管理
    void handle_client(...) {
        // 单客户端模式
        // repl_sink_->set_client_socket(session->socket_ptr);
        
        // 广播模式
        repl_sink_->add_client_socket(session->socket_ptr);
    }
    
    void cleanup_client(...) {
        // 单客户端模式
        // repl_sink_->clear_client_socket();
        
        // 广播模式
        repl_sink_->remove_client_socket(session->socket_ptr);
    }
};
```

### 方法 2: 使用配置宏（推荐）

**在 config.h 中添加：**
```cpp
// config.h
namespace Config {
    // REPL 输出模式
    // true: 广播到所有客户端
    // false: 只发送到当前活动客户端
    constexpr bool REPL_BROADCAST_MODE = false;
}
```

**在 LuaReplServer.hpp 中使用：**
```cpp
#include "config.h"

#if Config::REPL_BROADCAST_MODE
    #include "ReplSinkBroadcast.hpp"
    using ReplSinkType = repl_broadcast_sink_mt;
#else
    #include "ReplSink.hpp"
    using ReplSinkType = repl_sink_mt;
#endif

class LuaReplServer {
    std::shared_ptr<ReplSinkType> repl_sink_;
    
    void handle_client(...) {
#if Config::REPL_BROADCAST_MODE
        repl_sink_->add_client_socket(session->socket_ptr);
#else
        repl_sink_->set_client_socket(session->socket_ptr);
#endif
    }
    
    void cleanup_client(...) {
#if Config::REPL_BROADCAST_MODE
        repl_sink_->remove_client_socket(session->socket_ptr);
#else
        repl_sink_->clear_client_socket();
#endif
    }
};
```

## 性能对比

### 单客户端模式
- **网络开销：** 低（只发送到一个客户端）
- **CPU 开销：** 低
- **内存开销：** 低
- **适用场景：** 日常开发调试

### 广播模式
- **网络开销：** 高（发送到 N 个客户端）
- **CPU 开销：** 中等（需要遍历客户端列表）
- **内存开销：** 中等（维护客户端列表）
- **适用场景：** 多人协作、监控

### 性能测试数据（示例）

假设有 3 个客户端连接，每秒产生 100 条 console->info 输出：

| 模式 | 网络流量 | CPU 使用 | 延迟 |
|------|---------|---------|------|
| 单客户端 | ~10 KB/s | ~1% | <1ms |
| 广播 | ~30 KB/s | ~3% | <5ms |

## 使用建议

### 推荐使用单客户端模式（默认）
- 大多数情况下足够使用
- 性能更好
- 实现更简单

### 何时使用广播模式
1. **多人协作调试**
   - 团队成员需要同时查看输出
   - 远程协助调试

2. **监控和日志收集**
   - 一个客户端用于交互
   - 另一个客户端用于记录日志

3. **教学演示**
   - 讲师操作，学生观看
   - 多个屏幕显示相同内容

## 混合模式（高级）

如果需要更灵活的控制，可以实现混合模式：

```cpp
class repl_hybrid_sink : public spdlog::sinks::base_sink<Mutex> {
    // 主客户端（执行命令的客户端）
    std::shared_ptr<tcp::socket> primary_client_;
    
    // 观察者客户端（只接收输出）
    std::vector<std::shared_ptr<tcp::socket>> observer_clients_;
    
    void sink_it_(...) {
        // 发送到主客户端
        if (primary_client_) {
            write_to_socket(primary_client_, msg);
        }
        
        // 发送到所有观察者
        for (auto& observer : observer_clients_) {
            write_to_socket(observer, msg);
        }
    }
};
```

这样可以：
- 主客户端可以执行命令并接收输出
- 观察者客户端只接收输出，不能执行命令
- 平衡性能和功能

## 故障排除

### 问题：广播模式下某些客户端收不到输出
**原因：** 客户端 socket 可能已关闭或出错
**解决：** 广播 sink 会自动移除无效的客户端，重新连接即可

### 问题：单客户端模式下输出发送到错误的客户端
**原因：** 多个客户端同时执行命令
**解决：** 使用广播模式，或确保同一时间只有一个客户端执行命令

### 问题：性能下降
**原因：** 广播模式下客户端过多，或输出频率过高
**解决：**
1. 减少客户端数量
2. 降低日志级别
3. 使用采样输出
4. 切换到单客户端模式
