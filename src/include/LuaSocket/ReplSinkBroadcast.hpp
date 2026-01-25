#pragma once

#include <spdlog/sinks/base_sink.h>
#include <spdlog/details/null_mutex.h>
#include <mutex>
#include <memory>
#include <vector>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

// 广播版本的 REPL sink，将日志输出到所有连接的客户端
// 如果需要所有客户端都接收 console 输出，使用此版本替代 ReplSink.hpp
template<typename Mutex>
class repl_broadcast_sink : public spdlog::sinks::base_sink<Mutex> {
public:
    repl_broadcast_sink() = default;
    
    // 添加客户端 socket
    void add_client_socket(std::shared_ptr<tcp::socket> socket) {
        std::lock_guard<Mutex> lock(this->mutex_);
        client_sockets_.push_back(socket);
    }
    
    // 移除客户端 socket
    void remove_client_socket(std::shared_ptr<tcp::socket> socket) {
        std::lock_guard<Mutex> lock(this->mutex_);
        client_sockets_.erase(
            std::remove(client_sockets_.begin(), client_sockets_.end(), socket),
            client_sockets_.end()
        );
    }
    
    // 清除所有客户端
    void clear_all_clients() {
        std::lock_guard<Mutex> lock(this->mutex_);
        client_sockets_.clear();
    }
    
    // 获取活动客户端数量
    size_t client_count() const {
        std::lock_guard<Mutex> lock(this->mutex_);
        return client_sockets_.size();
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (client_sockets_.empty()) {
            return;
        }
        
        try {
            spdlog::memory_buf_t formatted;
            this->formatter_->format(msg, formatted);
            formatted.push_back('\n');
            
            // 广播到所有客户端
            auto it = client_sockets_.begin();
            while (it != client_sockets_.end()) {
                auto& socket = *it;
                
                if (!socket || !socket->is_open()) {
                    // 移除无效的 socket
                    it = client_sockets_.erase(it);
                    continue;
                }
                
                try {
                    boost::system::error_code ec;
                    boost::asio::write(*socket, 
                                     boost::asio::buffer(formatted.data(), formatted.size()), 
                                     ec);
                    
                    if (ec) {
                        // 写入失败，移除此客户端
                        it = client_sockets_.erase(it);
                        continue;
                    }
                } catch (const std::exception&) {
                    // 异常，移除此客户端
                    it = client_sockets_.erase(it);
                    continue;
                }
                
                ++it;
            }
        } catch (const std::exception&) {
            // 忽略格式化异常
        }
    }

    void flush_() override {
        // REPL 不需要 flush
    }

private:
    std::vector<std::shared_ptr<tcp::socket>> client_sockets_;
};

using repl_broadcast_sink_mt = repl_broadcast_sink<std::mutex>;
using repl_broadcast_sink_st = repl_broadcast_sink<spdlog::details::null_mutex>;
