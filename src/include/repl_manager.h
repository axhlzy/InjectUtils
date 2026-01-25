#ifndef REPL_MANAGER_H
#define REPL_MANAGER_H

#include "LuaLibrary.h"
#include <string>
#include <vector>

/**
 * REPL 管理器
 * 提供不同模式的 Lua REPL 启动和管理
 */

/**
 * 获取 Lua 全局函数列表
 * @param L Lua 状态机
 * @return 函数名列表
 */
std::vector<std::string> getLuaCommands(lua_State *L);

/**
 * 启动 Socket 模式的 REPL 服务器
 * 在目标应用进程中运行，等待客户端连接
 * @param L Lua 状态机
 */
void startReplSocket(lua_State *L);

/**
 * 启动本地 REPL 客户端
 * 连接到远程 REPL 服务器
 */
void startReplClient();

/**
 * 启动调试模式的 REPL
 * 直接在本地执行 Lua 命令
 * @param L Lua 状态机
 */
void startReplDebug(lua_State *L);

/**
 * 根据启动类型自动选择 REPL 模式
 * @param L Lua 状态机
 */
void startRepl(lua_State *L);

#endif // REPL_MANAGER_H
