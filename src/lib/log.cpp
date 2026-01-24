#include "log.h"

std::shared_ptr<spdlog::logger> console;
std::shared_ptr<spdlog::logger> android_logger;

void init_logger() {

    // console logger
    if (!console) {
        console = spdlog::stdout_color_st("console", spdlog::color_mode::automatic);
        console->set_pattern("%^[%L] %v%$");
#ifdef DEBUG_PROJECT
        console->set_level(spdlog::level::debug);
#else
        console->set_level(spdlog::level::info);
#endif
    }

    // android logcat
    if (!android_logger) {
        android_logger = spdlog::android_logger_st("android_logger", TAG);
#ifdef DEBUG_PROJECT
        android_logger->set_level(spdlog::level::debug);
#else
        android_logger->set_level(spdlog::level::info);
#endif
    }
}