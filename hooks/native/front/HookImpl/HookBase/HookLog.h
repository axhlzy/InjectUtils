#pragma once

#include <android/log.h>

#ifndef HK_LOG
#define HK_LOG "ZZZ"
#endif

#define logd(...) __android_log_print(ANDROID_LOG_DEBUG, HK_LOG, __VA_ARGS__)
#define loge(...) __android_log_print(ANDROID_LOG_ERROR, HK_LOG, __VA_ARGS__)
#define logi(...) __android_log_print(ANDROID_LOG_INFO, HK_LOG, __VA_ARGS__)
#define logw(...) __android_log_print(ANDROID_LOG_WARN, HK_LOG, __VA_ARGS__)