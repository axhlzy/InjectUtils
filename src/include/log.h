#include <android/log.h>

static const char *TAG = "ZZZ";

#define logd(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define loge(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define logi(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define logw(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#if !defined(lua_printf)
#define lua_printf(s, l) fwrite((s), sizeof(char), (l), stdout)
#endif

#include "spdlog/spdlog.h"

extern std::shared_ptr<spdlog::logger> console;
extern std::shared_ptr<spdlog::logger> android_logger;

__attribute__((constructor)) void init_logger();