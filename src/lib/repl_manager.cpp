#include "repl_manager.h"
#include "config.h"
#include "log.h"
#include "main.h"
#include "lua_function_list.h"
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
        io_context.run();
    } catch (const boost::system::system_error &e) {
        std::string error_msg = fmt::format(
            "[!] Socket error: {} (code: {})", e.what(), e.code().value());
        console->error("{}", error_msg);
        loge("%s", error_msg.c_str());

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

// 获取常用的 Lua 命令和关键字用于自动补全
static std::vector<std::string> getDefaultLuaSuggestions() {
    std::vector<std::string> suggestions = {
        // 常用 Lua 函数
        "print", "type", "tonumber", "tostring", "pairs", "ipairs",
        "next", "select", "assert", "error", "pcall", "xpcall",
        "getmetatable", "setmetatable", "rawget", "rawset", "rawequal",
        "collectgarbage", "dofile", "loadfile", "load", "require",
        
        // 表操作
        "table.concat", "table.insert", "table.remove", "table.sort",
        "table.pack", "table.unpack", "table.move",
        
        // 字符串操作
        "string.byte", "string.char", "string.dump", "string.find",
        "string.format", "string.gmatch", "string.gsub", "string.len",
        "string.lower", "string.match", "string.rep", "string.reverse",
        "string.sub", "string.upper",
        
        // 数学函数
        "math.abs", "math.acos", "math.asin", "math.atan", "math.ceil",
        "math.cos", "math.deg", "math.exp", "math.floor", "math.log",
        "math.max", "math.min", "math.modf", "math.rad", "math.random",
        "math.randomseed", "math.sin", "math.sqrt", "math.tan",
        
        // IO 操作
        "io.open", "io.close", "io.read", "io.write", "io.flush",
        "io.lines", "io.input", "io.output", "io.tmpfile",
        
        // OS 操作
        "os.clock", "os.date", "os.difftime", "os.execute", "os.exit",
        "os.getenv", "os.remove", "os.rename", "os.time", "os.tmpname",
        
        // 控制命令
        "exit", "quit", "q", "quitLua",
        
        "help"
    };
    
    // 添加自定义绑定的函数
    auto customFunctions = getCustomLuaFunctions();
    suggestions.insert(suggestions.end(), customFunctions.begin(), customFunctions.end());
    
    return suggestions;
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
    console->info("[*] Press TAB for auto-completion, Ctrl+R for history search");

    // 获取默认的 Lua 命令补全列表
    std::vector<std::string> suggestions = getDefaultLuaSuggestions();

    installRepl(suggestions, [&](const std::string &input) {
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
