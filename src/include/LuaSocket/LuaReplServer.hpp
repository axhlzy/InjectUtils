#pragma once

#include "lauxlib.h"
#include "log.h"
#include "ReplSink.hpp"
#include <boost/asio.hpp>
#include <fmt/format.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using boost::asio::ip::tcp;

#ifndef LUA_REPL_BUFFER_SIZE
#define LUA_REPL_BUFFER_SIZE 128 * 1024  // 128KB 统一缓冲区
#endif

class LuaReplServer {
public:
    LuaReplServer(boost::asio::io_context &io_context, int port, lua_State *L)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), 
          socket_(io_context), 
          main_lua_state_(L),
          next_client_id_(0) {
        
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
        
        // 创建 REPL sink 并添加到 console logger
        repl_sink_ = std::make_shared<repl_sink_mt>();
        console->sinks().push_back(repl_sink_);
        
        auto endpoint = acceptor_.local_endpoint();
        std::string listen_msg = fmt::format("[*] Lua REPL Server listening on {}:{}", 
                                             endpoint.address().to_string(), 
                                             endpoint.port());
        std::cout << listen_msg << std::endl;
        logd("%s", listen_msg.c_str());
        
        std::cout << "[*] Waiting for client connections..." << std::endl;
        std::cout << "[*] Connect using: nc 127.0.0.1 " << port << std::endl;
        
        start_accept();
    }

    ~LuaReplServer() {
        // 从 console logger 中移除 repl sink
        if (repl_sink_) {
            auto& sinks = console->sinks();
            sinks.erase(std::remove(sinks.begin(), sinks.end(), repl_sink_), sinks.end());
        }
        
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.clear();
    }

private:
    struct ClientSession {
        int id;
        int socket_fd;
        lua_State* lua_thread;  // 每个客户端独立的 Lua 协程
        std::shared_ptr<tcp::socket> socket_ptr;
        
        ClientSession(int id, int fd, lua_State* thread, std::shared_ptr<tcp::socket> sock)
            : id(id), socket_fd(fd), lua_thread(thread), socket_ptr(sock) {}
    };

    void start_accept() {
        acceptor_.async_accept(socket_, [this](const boost::system::error_code &error) {
            handle_accept(error);
        });
    }

    void handle_accept(const boost::system::error_code &error) {
        if (!error) {
            try {
                auto remote_ep = socket_.remote_endpoint();
                std::string client_info = fmt::format("[*] Client connected from {}:{}", 
                                                      remote_ep.address().to_string(),
                                                      remote_ep.port());
                std::cout << client_info << std::endl;
                logd("%s", client_info.c_str());
                
                int client_id = next_client_id_++;
                int client_fd = socket_.native_handle();
                
                // 为每个客户端创建独立的 Lua 线程（协程）
                lua_State* client_thread = lua_newthread(main_lua_state_);
                
                // 保存线程引用，防止被 GC
                lua_pushvalue(main_lua_state_, -1);
                std::string ref_key = fmt::format("client_thread_{}", client_id);
                lua_setfield(main_lua_state_, LUA_REGISTRYINDEX, ref_key.c_str());
                
                auto socket_ptr = std::make_shared<tcp::socket>(std::move(socket_));
                auto session = std::make_shared<ClientSession>(client_id, client_fd, client_thread, socket_ptr);
                
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    clients_[client_id] = session;
                }
                
                // 设置客户端专用的 print 函数
                setup_client_print(client_thread, session);
                
                std::thread(&LuaReplServer::handle_client, this, session).detach();
                
            } catch (const std::exception &e) {
                std::string error_msg = fmt::format("[!] Error handling client: {}", e.what());
                std::cerr << error_msg << std::endl;
                loge("%s", error_msg.c_str());
            }
        } else {
            std::string error_msg = fmt::format("[!] Accept error: {} (code: {})", 
                                                error.message(), error.value());
            std::cerr << error_msg << std::endl;
            loge("%s", error_msg.c_str());
        }
        start_accept();
    }

    void setup_client_print(lua_State* L, std::shared_ptr<ClientSession> session) {
        // 保存 session 指针到 Lua 注册表
        lua_pushlightuserdata(L, session.get());
        lua_setfield(L, LUA_REGISTRYINDEX, "client_session");
        
        // 设置自定义 print 函数
        lua_pushcfunction(L, [](lua_State *L) -> int {
            // 获取 session
            lua_getfield(L, LUA_REGISTRYINDEX, "client_session");
            auto* session = static_cast<ClientSession*>(lua_touserdata(L, -1));
            lua_pop(L, 1);
            
            if (!session || !session->socket_ptr || !session->socket_ptr->is_open()) {
                return 0;
            }
            
            // 构建输出字符串
            std::string output;
            int n = lua_gettop(L);
            lua_getglobal(L, "tostring");
            
            for (int i = 1; i <= n; i++) {
                lua_pushvalue(L, -1);  // tostring function
                lua_pushvalue(L, i);   // argument
                lua_call(L, 1, 1);
                
                size_t len;
                const char *s = lua_tolstring(L, -1, &len);
                if (s == nullptr) {
                    return luaL_error(L, "'tostring' must return a string to 'print'");
                }
                
                if (i > 1) output += "\t";
                output.append(s, len);
                lua_pop(L, 1);
            }
            output += "\n";
            
            // 同步写入 socket
            try {
                boost::system::error_code ec;
                boost::asio::write(*session->socket_ptr, boost::asio::buffer(output), ec);
                if (ec) {
                    std::cerr << "[!] Write error: " << ec.message() << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] Print error: " << e.what() << std::endl;
            }
            
            return 0;
        });
        lua_setglobal(L, "print");
    }

    void handle_client(std::shared_ptr<ClientSession> session) {
        try {
            boost::system::error_code error;
            std::vector<char> buffer(LUA_REPL_BUFFER_SIZE);
            
            // 设置当前客户端的 socket 到 repl sink
            repl_sink_->set_client_socket(session->socket_ptr);
            
            std::string welcome = fmt::format("[*] Connected to Lua REPL (Client ID: {})\n", session->id);
            boost::asio::write(*session->socket_ptr, boost::asio::buffer(welcome), error);
            
            while (session->socket_ptr->is_open()) {
                std::memset(buffer.data(), 0, buffer.size());
                size_t len = session->socket_ptr->read_some(boost::asio::buffer(buffer), error);
                
                if (error == boost::asio::error::eof) {
                    std::cout << fmt::format("[*] Client {} disconnected", session->id) << std::endl;
                    break;
                } else if (error) {
                    throw boost::system::system_error(error);
                }

                std::string input(buffer.data(), len);
                
                // 移除末尾的换行符
                while (!input.empty() && (input.back() == '\n' || input.back() == '\r')) {
                    input.pop_back();
                }
                
                if (input.empty()) continue;
                
                if (input == "exit" || input == "q" || input == "quit") {
                    std::string bye = "[*] Disconnecting...\n";
                    boost::asio::write(*session->socket_ptr, boost::asio::buffer(bye), error);
                    break;
                }

                // 在客户端的 Lua 线程中执行代码
                int status = luaL_dostring(session->lua_thread, input.c_str());
                if (status != LUA_OK) {
                    const char *msg = lua_tostring(session->lua_thread, -1);
                    std::string error_msg = fmt::format("[ERROR] {}\n", msg ? msg : "unknown error");
                    boost::asio::write(*session->socket_ptr, boost::asio::buffer(error_msg), error);
                    lua_pop(session->lua_thread, 1);
                }
            }
        } catch (const std::exception &e) {
            std::cerr << fmt::format("[!] Exception in client {} session: {}", session->id, e.what()) << std::endl;
            logd("[!] Exception in client %d session: %s", session->id, e.what());
        }

        // 清理客户端
        cleanup_client(session);
    }

    void cleanup_client(std::shared_ptr<ClientSession> session) {
        try {
            // 清除 repl sink 中的客户端 socket
            if (repl_sink_) {
                repl_sink_->clear_client_socket();
            }
            
            if (session->socket_ptr && session->socket_ptr->is_open()) {
                boost::system::error_code ec;
                session->socket_ptr->close(ec);
            }
            
            // 从客户端列表中移除
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                clients_.erase(session->id);
            }
            
            // 清理 Lua 线程引用
            std::string ref_key = fmt::format("client_thread_{}", session->id);
            lua_pushnil(main_lua_state_);
            lua_setfield(main_lua_state_, LUA_REGISTRYINDEX, ref_key.c_str());
            
            std::cout << fmt::format("[*] Client {} cleaned up", session->id) << std::endl;
        } catch (const std::exception& e) {
            std::cerr << fmt::format("[!] Cleanup error for client {}: {}", session->id, e.what()) << std::endl;
        }
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
    lua_State *main_lua_state_;
    
    std::mutex clients_mutex_;
    std::map<int, std::shared_ptr<ClientSession>> clients_;
    std::atomic<int> next_client_id_;
    std::shared_ptr<repl_sink_mt> repl_sink_;
};