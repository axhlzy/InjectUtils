//
// Created by lzy on 2023/9/27.
//
#include "art_hook.h"
#include "Common.h"
#include "art_utils.h"
#include "hook/native/front/HookManager.h"
#include "xdl.h"

static std::shared_ptr<spdlog::logger> logger;

void ArtManager::Hook() {

#if defined(__aarch64__)
    return;
#endif

    INIT_LOGGER();

    void *handle = xdl_open(xorstr_("libart.so"), RTLD_LAZY);

    static void *ArtMethod_Invoke_ptr = xdl_sym(handle, xorstr_("_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"), nullptr);
    if (ArtMethod_Invoke_ptr == nullptr) {
        LOGE("xdl_sym _ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc failed");
        return;
    }

    /**
     * _ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc
     * art::ArtMethod::Invoke(art::Thread*, unsigned int*, unsigned int, art::JValue*, char const*) <- demangleName
     * void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result, const char* shorty)
     * ref https://cs.android.com/android/platform/superproject/+/master:art/runtime/art_method.cc;l=365
     */
    static map<string, int> countTimes = {};
    static vector<string> filterContainStr = {};
    static vector<string> filterStr = {"java.lang.", "dalvik.system.", "java.nio.", "android.", "sun.misc.", "libcore.", "kotlinx.coroutines",
                                       "java.util.", "java.io.", "java.net.", "android.view.", "org.chromium"};
    HookManager::registerHook(ArtMethod_Invoke_ptr, HOOK_DOBBY, [](ArtMethod *artMethod, void *thread, uint32_t *args, uint32_t args_size, void *result, const char *shorty) {
        const string method_name = ArtUtils::PrettyMethod(artMethod);
        if (++countTimes[method_name] > 20)
            goto end;
        for (const auto &filter : filterContainStr)
            if (method_name.find(filter) != string::npos)
                goto log;
        for (const auto &filter : filterStr)
            if (method_name.find(filter) != string::npos)
                goto end;
    log:
        // LOGI("called ArtMethod::Invoke( artMethod={}, thread={}, args={}, args_size={}, result={}, shorty={} )", (void*)artMethod, thread, (void*)args, args_size, result, shorty);
        LOGD("\tartMethod => {}", method_name);
    end:
        return HookManager::srcCall(ArtMethod_Invoke_ptr, artMethod, thread, args, args_size, result, shorty);
    });
}
