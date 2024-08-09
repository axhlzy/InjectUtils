#include "art_test.h"

// __attribute__((constructor))
void testArt() {

    return;

    using namespace art;

    JavaVM *vm = nullptr;
    jsize nVMs = 0;
    JNI_GetCreatedJavaVMs(&vm, 1, &nVMs);

    if (vm == nullptr) {
        loge("[*] GetCreatedJavaVMs Failed");
        return;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        loge("[*] GetEnv Failed");
        return;
    }

    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        loge("[*] AttachCurrentThread Failed");
        return;
    }

    // android.widget.TextView setText
    jclass cls = env->FindClass("android/widget/TextView");
    jmethodID mid = env->GetMethodID(cls, "setText", "(Ljava/lang/CharSequence;)V");
    jobject obj_ref = env->ToReflectedMethod(cls, mid, JNI_FALSE);
    logd("[*] jclass %p | jmethodID %p | jobject %p", cls, mid, obj_ref);

    // libcore/ojluni/annotations/hiddenapi/java/lang/reflect/Executable.java getArtMethod
    auto ExecutableClass = env->FindClass("java/lang/reflect/Executable");
    // private long artMethod;
    auto fieldId = env->GetFieldID(ExecutableClass, "artMethod", "J");
    auto artM = env->GetLongField(obj_ref, fieldId);
    logd("[*] artMethod = %p", artM);

    ArtMethod *artMethod = reinterpret_cast<ArtMethod *>(artM);
    auto s = artMethod->PrettyMethod();
    logd("[*] %s", s.c_str());
}