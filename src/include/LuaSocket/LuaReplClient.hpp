#include <boost/asio.hpp>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>

using namespace boost::asio;
using ip::tcp;
using std::cerr;
using std::cout;
using std::endl;
using ResponseHandler = std::function<void(const std::string &)>;

constexpr long MAXLEN = 0x1000 * 0x1000 * 2;

class LuaReplClient {
public:
    LuaReplClient(const std::string &server_port, const std::string &server_ip = "127.0.0.1")
        : server_ip_(server_ip),
          server_port_(server_port),
          io_context_(),
          socket_(io_context_),
          reply_(new char[MAXLEN]) {
        work_guard = std::make_unique<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(
            boost::asio::make_work_guard(io_context_));
    }

    ~LuaReplClient() {
        io_context_.stop();
        if (thread_ && thread_->joinable()) {
            thread_->join();
        }
    }

    void connect() {
        while (true) {
            try {
                tcp::resolver resolver(io_context_);
                auto endpoints = resolver.resolve(server_ip_, server_port_);
                boost::asio::connect(socket_, endpoints);
                cout << "Connected to server at " << server_ip_ << ":" << server_port_ << endl;

                start_receive();
                thread_ = std::make_unique<std::thread>([this]() { io_context_.run(); });
                break;
            } catch (const std::exception &e) {
                cerr << "Connection error: " << e.what() << endl;
                static int count = 0;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (++count > 10)
                    exit(1);
            }
        }
    }

    void send_message(const std::string &message) {
        boost::asio::async_write(socket_, boost::asio::buffer(message), [this](boost::system::error_code ec, std::size_t /*length*/) {
            if (ec) {
                cerr << "Send failed: " << ec.message();
            }
        });
    }

    void close_connect() {
        socket_.close();
        work_guard.reset();
    }

private:
    void start_receive() {
        socket_.async_read_some(boost::asio::buffer(reply_.get(), MAXLEN),
                                [this](boost::system::error_code ec, std::size_t length) {
                                    if (!ec) {
                                        cout << std::string(reply_.get(), length) << endl;
                                        start_receive();
                                    } else {
                                        cerr << "Receive error: " << ec.message() << endl;
                                        socket_.close();
                                    }
                                });
    }

    std::string server_ip_;
    std::string server_port_;
    io_context io_context_;
    tcp::socket socket_;
    std::unique_ptr<char[]> reply_;
    std::unique_ptr<std::thread> thread_;
    std::unique_ptr<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard;
};
