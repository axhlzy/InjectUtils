#include "lauxlib.h"
#include "log.h"
#include "magic_enum.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include <map>
#include <string>
#include <thread>

using boost::asio::ip::tcp;

constexpr long MAXLEN = 0x1000;

class LuaReplServer {
public:
    LuaReplServer(boost::asio::io_context &io_context, int port, lua_State *L)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), socket_(io_context), lua_state_(L) {
        start_accept();
        lua_pushcfunction(L, l_print);
        lua_setglobal(L, "print");
    }

private:
    void start_accept() {
        acceptor_.async_accept(socket_, boost::bind(&LuaReplServer::handle_accept, this, boost::asio::placeholders::error));
    }

    void handle_accept(const boost::system::error_code &error) {
        if (!error) {
            int clientSocket = socket_.native_handle();
            std::cout << "[*] Client connected. IP: " << socket_.remote_endpoint().address().to_string() << std::endl;
            logd("[*] Client connected. IP: %s", socket_.remote_endpoint().address().to_string().c_str());
            LuaReplServer::soc_client = clientSocket;
            dup2(clientSocket, STDOUT_FILENO);
            std::thread(&LuaReplServer::handle_client, this, std::move(socket_), lua_state_, clientSocket).detach();
        } else {
            std::cerr << "[*] Accept error: " << error.message() << std::endl;
            logd("[*] Accept error:  %s", error.message().c_str());
        }
        start_accept();
    }

    void handle_client(tcp::socket client_socket, lua_State *L, int clientSocket) {
        try {
            boost::system::error_code error;
            char buffer[MAXLEN];
            while (true) {
                std::memset(buffer, 0, sizeof(buffer));
                size_t len = client_socket.read_some(boost::asio::buffer(buffer), error);
                if (error == boost::asio::error::eof) {
                    std::cout << "[*] Client disconnected." << std::endl;
                    logd("[*] Client disconnected.");
                    pthread_exit(0); // 直接退出
                    break;
                } else if (error) {
                    throw boost::system::system_error(error);
                }

                std::string input(buffer, len);
                if (input == "exit" || input == "q") {
                    boost::asio::write(client_socket, boost::asio::buffer("Client requested exit."), error);
                    break;
                }

                int status = luaL_dostring(L, input.c_str());
                if (status != LUA_OK) {
                    const char *msg = lua_tostring(L, -1);
                    lua_writestringerror("%s\n", msg);
                    boost::asio::write(client_socket, boost::asio::buffer(msg, strlen(msg)), error);
                    lua_pop(L, 1);
                } else {
                    // boost::asio::write(client_socket, boost::asio::buffer("OK"), error);
                }
            }
        } catch (std::exception &e) {
            std::cerr << "[*] Exception in client session: " << e.what() << std::endl;
            logd("[*] Exception in client session: %s", e.what());
        }

        client_socket.close();
        lua_close(L);
    }

    static int l_print(lua_State *L) {
        int n = lua_gettop(L);
        lua_getglobal(L, "tostring");
        for (int i = 1; i <= n; i++) {
            const char *s;
            size_t len;
            lua_pushvalue(L, -1);
            lua_pushvalue(L, i);
            lua_call(L, 1, 1);
            s = lua_tolstring(L, -1, &len);
            if (s == nullptr) {
                return luaL_error(L, "'tostring' must return a string to 'print'");
            }
            if (i > 1) {
                write(LuaReplServer::soc_client, "\t", 1);
            }
            write(LuaReplServer::soc_client, s, len);
            lua_pop(L, 1);
        }
        write(LuaReplServer::soc_client, "\n", 1);
        return 0;
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
    lua_State *lua_state_;
    inline static int soc_client;
};