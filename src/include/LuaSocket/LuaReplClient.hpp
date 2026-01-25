#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>
#include <atomic>

using namespace boost::asio;
using ip::tcp;
using std::cerr;
using std::cout;
using std::endl;

#ifndef LUA_REPL_BUFFER_SIZE
#define LUA_REPL_BUFFER_SIZE 128 * 1024  // 128KB 统一缓冲区
#endif

class LuaReplClient {
public:
    LuaReplClient(const std::string &server_port, const std::string &server_ip = "127.0.0.1")
        : server_ip_(server_ip),
          server_port_(server_port),
          io_context_(),
          socket_(io_context_),
          reply_buffer_(LUA_REPL_BUFFER_SIZE),
          connected_(false) {
        work_guard_ = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(
            boost::asio::make_work_guard(io_context_));
    }

    ~LuaReplClient() {
        disconnect();
    }

    // 改进的连接方法，支持超时和重试
    bool connect(int max_retries = 30, int retry_interval_ms = 1000) {
        for (int attempt = 0; attempt < max_retries; ++attempt) {
            try {
                tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(server_ip_, server_port_);
                boost::asio::connect(socket_, endpoints);
                
                connected_ = true;
                cout << "[*] Connected to server at " << server_ip_ << ":" << server_port_ << endl;

                start_receive();
                io_thread_ = std::make_unique<std::thread>([this]() { 
                    io_context_.run(); 
                });
                
                return true;
            } catch (const std::exception &e) {
                if (attempt < max_retries - 1) {
                    cout << "[*] Connection attempt " << (attempt + 1) << "/" << max_retries 
                         << " failed: " << e.what() << endl;
                    std::this_thread::sleep_for(std::chrono::milliseconds(retry_interval_ms));
                } else {
                    cerr << "[!] Failed to connect after " << max_retries << " attempts: " 
                         << e.what() << endl;
                    return false;
                }
            }
        }
        return false;
    }

    void send_message(const std::string &message) {
        if (!is_connected()) {
            cerr << "[!] Cannot send message: not connected" << endl;
            return;
        }

        auto msg_copy = std::make_shared<std::string>(message);
        boost::asio::async_write(
            socket_, 
            boost::asio::buffer(*msg_copy),
            [msg_copy](boost::system::error_code ec, std::size_t /*length*/) {
                if (ec) {
                    cerr << "[!] Send failed: " << ec.message() << endl;
                }
            });
    }

    void disconnect() {
        if (connected_) {
            connected_ = false;
            boost::system::error_code ec;
            socket_.close(ec);
            work_guard_.reset();
            
            if (io_thread_ && io_thread_->joinable()) {
                io_context_.stop();
                io_thread_->join();
            }
        }
    }

    bool is_connected() const {
        return connected_ && socket_.is_open();
    }

    // 兼容旧接口
    void close_connect() {
        disconnect();
    }

private:
    void start_receive() {
        socket_.async_read_some(
            boost::asio::buffer(reply_buffer_),
            [this](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    cout << std::string(reply_buffer_.data(), length);
                    cout.flush();
                    start_receive();
                } else {
                    if (ec != boost::asio::error::operation_aborted) {
                        cerr << "[!] Receive error: " << ec.message() << endl;
                        handle_error(ec);
                    }
                }
            });
    }

    void handle_error(const boost::system::error_code& ec) {
        if (ec == boost::asio::error::eof || 
            ec == boost::asio::error::connection_reset) {
            cout << "[*] Server disconnected" << endl;
        }
        disconnect();
    }

    std::string server_ip_;
    std::string server_port_;
    io_context io_context_;
    tcp::socket socket_;
    std::vector<char> reply_buffer_;
    std::unique_ptr<std::thread> io_thread_;
    std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;
    std::atomic<bool> connected_;
};
