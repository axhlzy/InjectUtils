# REPL 使用示例

## 基本使用

### 1. 启动注入和 REPL
```bash
# 注入到目标进程
./inject-utils -p com.example.app

# 或使用 PID
./inject-utils -p 12345
```

### 2. 连接成功后的输出
```
[*] Injecting library into process 12345...
[*] Waiting for server to initialize...
[*] Starting local REPL client, connecting to port 9999
[*] Connection attempt 1/30 failed: Connection refused
[*] Connection attempt 2/30 failed: Connection refused
[*] Connected to server at 127.0.0.1:9999
[*] Connected! Type Lua commands or 'exit' to quit
>
```

### 3. 执行 Lua 命令
```lua
> print("Hello from REPL")
Hello from REPL

> console->info("This will appear in REPL")
[I] This will appear in REPL

> -- 调用 binds 中的函数
> xdl.open("libc.so")
[I] xdl_open -> 0x7b8c9a0000

> -- 所有 console->info 输出都会显示在 REPL 中
```

## console->info 重定向示例

### binds 中的代码
```cpp
// src/binds/qbdi.cpp
void registerMemRangeCB_dynstr(PTR start, PTR end) {
    // 这些 console->info 会自动显示在 REPL 客户端
    console->info("REG {} [ {:p} ~ {:p} ]", __FUNCTION__, start, end);
    
    _vm->addMemRangeCB(start, end, MemoryAccessType::MEMORY_WRITE, 
        [](QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, ...) {
            // 回调中的 console->info 也会显示在 REPL
            console->info("MemRangeCB dynstr: {:p}", (gprState->pc - _libBase));
            return QBDI::VMAction::CONTINUE;
        }, NULL);
}
```

### REPL 中看到的输出
```lua
> qbdi.registerMemRangeCB_dynstr(0x7b8c9a0000, 0x7b8c9a1000)
[I] REG registerMemRangeCB_dynstr [ 0x7b8c9a0000 ~ 0x7b8c9a1000 ]

> -- 当触发回调时
[I] MemRangeCB dynstr: 0x1234
[I]     0x7b8c9a0100 mov x0, x1
```

## 多客户端场景

### 场景 1: 使用本地 REPL 客户端
```bash
# 终端 1
./inject-utils -p 12345
> print("Client 1")
Client 1
```

### 场景 2: 使用 netcat 连接
```bash
# 终端 2
nc 127.0.0.1 9999
[*] Connected to Lua REPL (Client ID: 1)
> print("Client 2")
Client 2
```

### 注意事项
- 每个客户端有独立的 Lua 协程
- `console->info` 输出会发送到最后执行命令的客户端
- `print()` 输出只发送到当前客户端

## 输出流说明

### 1. console->info/error/warn
- 输出到：REPL 客户端 + stdout + logcat
- 使用场景：调试信息、状态提示
- 示例：`console->info("Hook installed at {:p}", addr);`

### 2. print()
- 输出到：当前 REPL 客户端
- 使用场景：Lua 脚本输出
- 示例：`print("Result:", result)`

### 3. logd/loge/logi/logw
- 输出到：logcat
- 使用场景：Android 日志
- 示例：`logd("Debug message");`

## 高级用法

### 1. 在 Lua 中调用 C++ 函数并查看输出
```lua
> -- 调用会产生 console->info 输出的函数
> xdl.iterate()
[I] dlpi_name: /system/lib64/libc.so
[I]     dlpi_addr: 0x7b8c9a0000
[I]     dlpi_phdr: 0x7b8c9a0040
[I]     dlpi_phnum: 8
[I] dlpi_name: /system/lib64/libm.so
...
```

### 2. 捕获回调中的输出
```lua
> -- 注册内存访问回调
> qbdi.registerMemRangeCB_got(0x7b8c9a0000, 0x7b8c9a1000)
[I] REG registerMemRangeCB_got [ 0x7b8c9a0000 ~ 0x7b8c9a1000 ]

> -- 触发内存访问时，回调中的 console->info 会显示
[I] MemRangeCB got: 0x1234
[I]     0x7b8c9a0100 ldr x0, [x1]
```

### 3. 实时监控
```lua
> -- 设置监控
> hook.install(0x7b8c9a0100, function()
>   console->info("Hook triggered!")
> end)

> -- 当 hook 触发时，会在 REPL 中看到
[I] Hook triggered!
```

## 故障排除

### 问题 1: 连接失败
```
[!] Failed to connect after 30 attempts
```
**解决方案：**
- 检查目标进程是否正在运行
- 检查端口是否被占用：`netstat -tuln | grep 9999`
- 增加等待时间或重试次数

### 问题 2: console->info 输出看不到
```lua
> -- 执行了命令但没有看到 console->info 输出
```
**可能原因：**
- 函数没有调用 console->info
- 输出被发送到其他客户端（多客户端场景）
- 检查 logcat：`adb logcat | grep InjectUtils`

### 问题 3: 客户端断开
```
[*] Server disconnected
```
**可能原因：**
- 目标进程崩溃
- 网络连接中断
- 服务器主动关闭

## 性能考虑

### console->info 的开销
- 每次调用会通过网络发送数据
- 在高频回调中使用可能影响性能
- 建议：在性能敏感的代码中使用条件日志

```cpp
// 不推荐：高频回调中无条件输出
_vm->addMemRangeCB(start, end, MEMORY_WRITE, [](auto...) {
    console->info("Callback triggered");  // 每次都发送
    return CONTINUE;
}, NULL);

// 推荐：使用计数器或条件
static int count = 0;
_vm->addMemRangeCB(start, end, MEMORY_WRITE, [](auto...) {
    if (++count % 100 == 0) {  // 每 100 次输出一次
        console->info("Callback triggered {} times", count);
    }
    return CONTINUE;
}, NULL);
```

## 最佳实践

1. **使用 console->info 进行调试**
   - 在开发和调试时使用
   - 生产环境可以通过日志级别控制

2. **使用 print() 输出结果**
   - Lua 脚本的输出使用 print()
   - 更轻量，只发送到当前客户端

3. **使用 logd/loge 记录重要事件**
   - 持久化日志使用 Android logcat
   - 可以通过 adb 查看历史日志

4. **避免在循环中频繁输出**
   - 使用计数器或采样
   - 考虑性能影响
