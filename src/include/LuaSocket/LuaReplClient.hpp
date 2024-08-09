#include <boost/asio.hpp>
#include <functional>
#include <iostream>

using boost::asio::ip::tcp;

using ResponseHandler = std::function<void(const std::string &)>;

constexpr long MAXLEN = 0x1000 * 1000;

class LuaReplClient {
public:
    LuaReplClient(const std::string &server_port, const std::string &server_ip = "127.0.0.1")
        : server_ip_(server_ip), server_port_(server_port), io_context_(), socket_(io_context_), reply_(new char[MAXLEN]) {}

    void connect() {
        while (true) {
            try {
                tcp::resolver resolver(io_context_);
                tcp::resolver::results_type endpoints = resolver.resolve(server_ip_, server_port_);
                boost::asio::connect(socket_, endpoints);
                std::cout << "Connected to server at " << server_ip_ << ":" << server_port_ << std::endl;
                break;
            } catch (const std::exception &e) {
                std::cerr << "Connection error: " << e.what() << std::endl;
                std::cout << "Retrying in 1 second..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void send_message(const std::string &message, ResponseHandler handler) {
        try {
            boost::asio::write(socket_, boost::asio::buffer(message));
            boost::system::error_code error;
            std::memset(reply_.get(), 0, MAXLEN);
            size_t reply_length = socket_.read_some(boost::asio::buffer(reply_.get(), MAXLEN), error);
            if (error == boost::asio::error::eof) {
                handler("Connection closed");
            } else if (error) {
                throw boost::system::system_error(error);
            } else {
                handler(std::string(reply_.get(), reply_length));
            }
        } catch (const std::exception &e) {
            std::cerr << "Communication error: " << e.what() << std::endl;
        }
    }

    void close() {
        boost::system::error_code ec;
        socket_.close(ec);
        if (ec) {
            std::cerr << "Close error: " << ec.message() << std::endl;
        } else {
            std::cout << "Connection closed." << std::endl;
        }
    }

private:
    std::string server_ip_;
    std::string server_port_;
    boost::asio::io_context io_context_;
    tcp::socket socket_;
    std::unique_ptr<char[]> reply_;
};