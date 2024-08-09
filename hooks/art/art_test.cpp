//
// Created by pc on 2023/8/22.
//

#include "art_test.h"
#include "art_utils.h"

static std::shared_ptr<spdlog::logger> logger;

using namespace ArtManager;

void Test::testArtMethod(JavaVM*, JNIEnv* env){

    INIT_LOGGER();

    // com.unity3d.player.UnityPlayerActivity
    jclass XlabHelper = env->FindClass("com/unity3d/player/UnityPlayerActivity");
    // public void onCreate(Bundle bundle)
    jmethodID onCreate = env->GetMethodID(XlabHelper, "onCreate", "(Landroid/os/Bundle;)V");
    ArtMethod* art_method = (ArtMethod*)Global<JNIHelper>::Get()->getArtMethod((jobject)env->ToReflectedMethod(XlabHelper, onCreate, JNI_FALSE));
    LOGD("art_method -> {}", (void*)art_method);

    void* handle = xdl_open(xorstr_("libart.so"), RTLD_LAZY);

    auto p_name_0 = ArtUtils::PrettyMethod(art_method);
    LOGD("PrettyMethod_0 -> {} entry_point {} ", p_name_0, (void*)art_method->ptr_sized_fields_.entry_point_from_quick_compiled_code_);
    auto p_name_1 = ArtUtils::PrettyMethod(++art_method);
    LOGD("PrettyMethod_1 -> {} entry_point {} ", p_name_1, (void*)art_method->ptr_sized_fields_.entry_point_from_quick_compiled_code_);

    // _ZN3art11interpreter20ExecuteSwitchImplCppILb1ELb0EEEvPNS0_17SwitchImplContextE
    static void* func_0 = xdl_sym(handle, xorstr_("_ZN3art11interpreter20ExecuteSwitchImplCppILb1ELb0EEEvPNS0_17SwitchImplContextE"), nullptr);
    // _ZN3art11interpreter20ExecuteSwitchImplCppILb0ELb1EEEvPNS0_17SwitchImplContextE
    static void* func_1 = xdl_sym(handle, xorstr_("_ZN3art11interpreter20ExecuteSwitchImplCppILb0ELb1EEEvPNS0_17SwitchImplContextE"), nullptr);
    // _ZN3art11interpreter20ExecuteSwitchImplCppILb1ELb1EEEvPNS0_17SwitchImplContextE
    static void* func_2 = xdl_sym(handle, xorstr_("_ZN3art11interpreter20ExecuteSwitchImplCppILb1ELb1EEEvPNS0_17SwitchImplContextE"), nullptr);
    // _ZN3art11interpreter20ExecuteSwitchImplCppILb0ELb0EEEvPNS0_17SwitchImplContextE
    static void* func_3 = xdl_sym(handle, xorstr_("_ZN3art11interpreter20ExecuteSwitchImplCppILb0ELb0EEEvPNS0_17SwitchImplContextE"), nullptr);

    return;

    LOGD("func_0 -> {} | func_1 -> {} | func_2 -> {} | func_3 -> {}", func_0, func_1, func_2, func_3);

    HookManager::registerHook(func_0, HOOK_DOBBY, *[](void* arg0, void* arg1, void* arg2, void* arg3, void* arg4){
        LOGD("called func_0");
        Utils::UnwindBacktrace();
        return HookManager::srcCall(func_0, arg0, arg1, arg2, arg3, arg4);
    });

    HookManager::registerHook(func_1, HOOK_DOBBY, *[](void* arg0, void* arg1, void* arg2, void* arg3, void* arg4){
        LOGD("called func_1");
        Utils::UnwindBacktrace();
        return HookManager::srcCall(func_1, arg0, arg1, arg2, arg3, arg4);
    });

    HookManager::registerHook(func_2, HOOK_DOBBY, *[](void* arg0, void* arg1, void* arg2, void* arg3, void* arg4){
        LOGD("called func_2");
        Utils::UnwindBacktrace();
        return HookManager::srcCall(func_2, arg0, arg1, arg2, arg3, arg4);
    });

    HookManager::registerHook(func_3, HOOK_DOBBY, *[](void* arg0, void* arg1, void* arg2, void* arg3, void* arg4){
        LOGD("called func_3");
        Utils::UnwindBacktrace();
        return HookManager::srcCall(func_3, arg0, arg1, arg2, arg3, arg4);
    });


}