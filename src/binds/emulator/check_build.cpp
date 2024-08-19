#include <cstring>
#include <jni.h>
#include <stdexcept>
#include <string>

/**
 *  通过 android/os/Build 类检测虚拟机,此方法要在JNI_OnLoad后才能开始检测，因为需要JNIEnv
 * @param env
 * @return true-检测到虚拟机 false-未检测到虚拟机
 */
bool check_build(JNIEnv *env) {
    if (env == nullptr) {
        throw std::runtime_error("env is null");
    }

    const char *fields[] = {
        "HARDWARE",
        "FINGERPRINT",
        "MODEL",
        "MANUFACTURER",
        "PRODUCT",
        "BRAND",
        "DEVICE"};

    bool ret = false;

    for (const char *fieldName : fields) {
        auto jFieldObj = env->GetStaticObjectField(
            env->FindClass("android/os/Build"),
            env->GetStaticFieldID(env->FindClass("android/os/Build"), fieldName, "Ljava/lang/String;"));

        auto jField = reinterpret_cast<jstring>(jFieldObj);

        const char *cField = env->GetStringUTFChars(jField, nullptr);

        if (cField) {
            if (std::strstr(cField, "vbox86") ||
                std::strstr(cField, "nox") ||
                std::strstr(cField, "ttVM_x86") ||
                std::strstr(cField, "Android") ||
                std::strstr(cField, "unknown") ||
                std::strstr(cField, "generic/sdk/generic") ||
                std::strstr(cField, "generic_x86/sdk_x86/generic_x86") ||
                std::strstr(cField, "Andy") ||
                std::strstr(cField, "ttVM_Hdragon") ||
                std::strstr(cField, "generic/google_sdk/generic") ||
                std::strstr(cField, "vbox86p") ||
                std::strstr(cField, "generic/vbox86p/vbox86p") ||
                std::strstr(cField, "google_sdk") ||
                std::strstr(cField, "Emulator") ||
                std::strstr(cField, "Droid4X") ||
                std::strstr(cField, "TiantianVM") ||
                std::strstr(cField, "Android SDK built for x86_64") ||
                std::strstr(cField, "Android SDK built for x86") ||
                std::strstr(cField, "Genymotion")) {
                ret = true;
            }

            // std::count << "check_Build => " << fieldName << " => " << cField << std::endl;
            env->ReleaseStringUTFChars(jField, cField);
        }

        env->DeleteLocalRef(jField);
    }

    return ret;
}
