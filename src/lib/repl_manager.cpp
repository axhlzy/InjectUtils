#include "repl_manager.h"
#include "config.h"
#include "log.h"
#include "main.h"
#include <LuaSocket/LuaReplClient.hpp>
#include <LuaSocket/LuaReplServer.hpp>

extern int installRepl(const std::vector<std::string> &suggestions,
                       std::function<void(const std::string &)> callback);

std::vector<std::string> getLuaCommands(lua_State *L) {
    std::vector<std::string> functionNames;
    
    lua_pushglobaltable(L);
    lua_pushnil(L);
    
    while (lua_next(L, -2) != 0) {
        if (lua_isfunction(L, -1)) {
            const char *name = lua_tostring(L, -2);
            if (name != nullptr) {
                functionNames.push_back(name);
            }
        }
        lua_pop(L, 1);
    }
    
    lua_pop(L, 1);
    return functionNames;
}

void startReplSocket(lua_State *L) {
    logd("[*] Starting Lua REPL | Socket Mode | Port: %d", SOCKET_PORT);
    console->info("[*] Starting Lua REPL Server on port {}", SOCKET_PORT);

    try {
        boost::asio::io_context io_context;
        LuaReplServer server(io_context, SOCKET_PORT, L);

        console->info("[*] Server started successfully, waiting for connections...");
        logd("[*] Server started successfully on port %d", SOCKET_PORT);

        io_context.run();
        
    } catch (const boost::system::system_error &e) {
        std::string error_msg = fmt::format(
            "[!] Socket error: {} (code: {})", e.what(), e.code().value());
        console->error("{}", error_msg);
        loge("%s", error_msg.c_str());

        // 检查常见错误
        if (e.code().value() == 98) {  // EADDRINUSE
            console->error("[!] Port {} is already in use", SOCKET_PORT);
            loge("[!] Port %d is already in use. Try: netstat -tuln | grep %d",
                 SOCKET_PORT, SOCKET_PORT);
        } else if (e.code().value() == 13) {  // EACCES
            console->error("[!] Permission denied. Need root?");
            loge("[!] Permission denied to bind port %d", SOCKET_PORT);
        }
        
    } catch (const std::exception &e) {
        std::string error_msg = fmt::format("[!] Server error: {}", e.what());
        console->error("{}", error_msg);
        loge("%s", error_msg.c_str());
    }
}

void startReplClient() {
    console->info("[*] Starting local REPL client, connecting to port {}", SOCKET_PORT);
    logd("[*] Connecting to localhost:%d", SOCKET_PORT);

    LuaReplClient client(std::to_string(SOCKET_PORT));

    // 使用改进的连接方法，支持重试和超时
    if (!client.connect(30, 1000)) {  // 30次重试，每次间隔1秒
        console->error("[!] Failed to connect to server");
        return;
    }

    console->info("[*] Connected! Type Lua commands or 'exit' to quit");

    installRepl({""}, [&](const std::string &input) {
        if (input == "exit" || input == "q") {
            console->info("[*] Closing connection...");
            client.disconnect();
        } else if (!input.empty()) {
            client.send_message(input);
        }
    });
}

void startReplDebug(lua_State *L) {
    logd("[*] Starting Lua REPL | Debug Mode");
    
    installRepl(getLuaCommands(L), [L](const std::string &input) {
        if (input == "exit" || input == "q") {
            exit(0);
        }
        
        if (input.empty()) {
            return;
        }
        
        int status = luaL_dostring(L, input.c_str());
        if (status != LUA_OK) {
            const char *msg = lua_tostring(L, -1);
            lua_writestringerror("%s\n", msg);
            lua_pop(L, 1);
        }
    });
}

void startRepl(lua_State *L) {
    switch (S_TYPE) {
        case START_TYPE::DEBUG:
            startReplDebug(L);
            break;
        case START_TYPE::SOCKET:
            startReplSocket(L);
            break;
        default:
            loge("[!] Unknown start type");
            break;
    }
}
