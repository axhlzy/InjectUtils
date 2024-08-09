#ifdef __cplusplus
extern "C" {
#endif

#include "frida-gum.h"
#include <fcntl.h>
#include <unistd.h>

#include "android/log.h"

#ifndef LOG_TAG
    #define LOG_TAG "ZZZ"
#endif

#define LOGD__(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

void test_frida_hook();

#ifdef __cplusplus
}
#endif