#pragma once

#include <spdlog/sinks/base_sink.h>
#include <spdlog/details/null_mutex.h>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

// 自定义 sink，将日志输出到 REPL 客户端
template<typename Mutex>
class repl_sink : public spdlog::sinks::base_sink<Mutex> {
public:
    repl_sink() = default;
    
    // 设置当前活动的客户端 socket
    void set_client_socket(std::shared_ptr<tcp::socket> socket) {
        std::lock_guard<Mutex> lock(this->mutex_);
        client_socket_ = socket;
    }
    
    // 清除客户端 socket
    void clear_client_socket() {
        std::lock_guard<Mutex> lock(this->mutex_);
        client_socket_.reset();
    }
    
    // 检查是否有活动客户端
    bool has_client() const {
        return client_socket_ && client_socket_->is_open();
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (!client_socket_ || !client_socket_->is_open()) {
            return;
        }
        
        try {
            spdlog::memory_buf_t formatted;
            this->formatter_->format(msg, formatted);
            
            // 添加换行符
            formatted.push_back('\n');
            
            boost::system::error_code ec;
            boost::asio::write(*client_socket_, 
                             boost::asio::buffer(formatted.data(), formatted.size()), 
                             ec);
            
            if (ec) {
                // 写入失败，清除 socket
                client_socket_.reset();
            }
        } catch (const std::exception&) {
            // 忽略异常，避免影响主程序
            client_socket_.reset();
        }
    }

    void flush_() override {
        // REPL 不需要 flush
    }

private:
    std::shared_ptr<tcp::socket> client_socket_;
};

using repl_sink_mt = repl_sink<std::mutex>;
using repl_sink_st = repl_sink<spdlog::details::null_mutex>;
