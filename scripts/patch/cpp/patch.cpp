#include "fmt/std.h"
#include "xdl.h"
#include <android/log.h>
#include <memory>

#define __MAIN__ __attribute__((constructor))
#define __EXIT__ __attribute__((destructor))
#define NOINLINE __attribute__((__noinline__))
#define INLINE __attribute__((__inline__))

static const char *TAG = "ZZZ";

#define logd(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define loge(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define logi(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define logw(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

class ST {
private:
    const char *msg;

public:
    ST(const char *msg) : msg(msg) {
        logd("-> %s", msg);
    }
    ~ST() {
        logd("<- %s", msg);
    }
};

__MAIN__
void magic() {
    std::make_shared<ST>(__FUNCTION__);
    void *cache = NULL;
    xdl_info_t info;
    xdl_addr((void *)magic, &info, &cache);
    // /data/app/com.tencent.tmgp.dpcq-_fKzJhtOuL24IIrfHQP7IA==/lib/arm64/libinject.so
    std::string tmp = std::string(info.dli_fname);
    // auto target = tmp.substr(tmp.find_last_of("/") + 1).c_str();
    const char *target = "libart.so";
    logd("target: %s", target);
    // xdl_addr_clean(&cache);

#ifdef __aarch64__
    const char *path = "/apex/com.android.runtime/lib64/";
#elif __arm__
    const char *path = "/apex/com.android.runtime/lib/";
#endif

    void *handle = xdl_open(fmt::format("{}{}", path, target).c_str(), XDL_DEFAULT);
    if (handle == NULL) {
        loge("Failed to open %s", target);
        return;
    } else {
        logi("Opened %s @ %p", target, handle);
    }

    xdl_info_t info_target;
    xdl_info(handle, XDL_DI_DLINFO, &info_target);

    xdl_addr_clean(&cache);
    xdl_close(handle);
}