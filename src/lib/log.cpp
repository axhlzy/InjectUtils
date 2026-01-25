#include "log.h"

std::shared_ptr<spdlog::logger> console;
std::shared_ptr<spdlog::logger> android_logger;

void init_logger() {

    // console logger
    if (!console) {
        console = spdlog::stdout_color_st("console", spdlog::color_mode::automatic);
#ifdef DEBUG_PROJECT
        console->set_level(spdlog::level::debug);
#else
        console->set_level(spdlog::level::info);
#endif
    }
    
    // 强制设置简洁格式：只显示日志级别和消息内容
    // 格式说明：%^ 开始颜色，%L 日志级别，%v 消息内容，%$ 结束颜色
    console->set_pattern("%^[%L] %v%$");

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