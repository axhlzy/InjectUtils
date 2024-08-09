#include "log.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <spdlog/sinks/android_sink.h>

std::shared_ptr<spdlog::logger> console;
std::shared_ptr<spdlog::logger> android_logger;

void init_logger() {

    // console logger
    if (!console) {
        console = spdlog::stdout_color_st("console", spdlog::color_mode::automatic);
        spdlog::set_pattern("[%T.%e] | %v");
        console->set_level(spdlog::level::debug);
    }

    // android logcat
    if (!android_logger) {
        android_logger = spdlog::android_logger_st("android_logger", TAG);
        android_logger->set_level(spdlog::level::debug);
    }
}