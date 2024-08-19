
#include "HookManager.h"
#include "android/art/runtime/art_method.h"
#include "bindings.h"

// bool JavaVMExt::LoadNativeLibrary(JNIEnv* env, const std::string& path, jobject class_loader, jclass caller_class, std::string* error_msg)
// _ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_
// ref : https://cs.android.com/android/platform/superproject/main/+/main:art/runtime/jni/java_vm_ext.cc;l=930;drc=09ad2d46df4f8ea96eff7c2ea6361feade1e6e1e;bpv=1;bpt=1
void HK_LoadNativeLibrary() {
    void *sym = DobbySymbolResolver("libart.so", "_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_");
    if (sym == nullptr) {
        console->error("[JavaVm] LoadNativeLibrary not found");
        return;
    }
    HK(sym, [=](void *instance, JNIEnv *env, const std::string &path, jobject class_loader, jclass caller_class, std::string *error_msg) {
        console->info("LoadNativeLibrary( instance:{}, env:{:p}, path:{}, class_loader:{}, caller_class:{}, error_msg:{})", instance, (void *)env, path, (void *)class_loader, (void *)caller_class, (void *)error_msg);
        return SrcCall(sym, instance, env, path, class_loader, caller_class, error_msg);
    });
    console->info("[JavaVm] register hook LoadNativeLibrary @ {}", sym);
}

#include "NativeBridge/NativeBridge.hpp"

// void* FindSymbol(const std::string& symbol_name, const char* shorty, android::JNICallType jni_call_type) REQUIRES(!Locks::mutator_lock_) {
//     return NeedsNativeBridge() ? FindSymbolWithNativeBridge(symbol_name, shorty, jni_call_type) : FindSymbolWithoutNativeBridge(symbol_name);
// }

// _ZN3art13SharedLibrary10FindSymbolERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKc
void HK_FindSymbol() {
    void *sym = DobbySymbolResolver("libart.so", "_ZN3art13SharedLibrary10FindSymbolERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKc");
    if (sym == nullptr) {
        console->error("[JavaVm] FindSymbol not found");
        return;
    }
    HK(sym, [=](void *SharedLibrary, const std::string &symbol_name, const char *shorty, JNICallType jni_call_type) -> void * {
        void *addr = SrcCall(sym, SharedLibrary, symbol_name, shorty);
        console->info("FindSymbol( sl:{}, symbol_name:{}, shorty:{}, jni_call_type:{} [ {} ]) => {}", SharedLibrary, symbol_name, shorty, (int)jni_call_type, magic_enum::enum_name(jni_call_type), addr);
        return addr;
    });
    console->info("[JavaVm] register hook FindSymbol @ {}", sym);
}

//   void* FindSymbolWithNativeBridge(const std::string& symbol_name, const char* shorty, android::JNICallType jni_call_type)
// _ZN3art13SharedLibrary29FindSymbolWithoutNativeBridgeERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE
void HK_FindSymbolWithoutNativeBridge() {
    void *sym = DobbySymbolResolver("libart.so", "_ZN3art13SharedLibrary29FindSymbolWithoutNativeBridgeERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE");
    if (sym == nullptr) {
        console->error("[JavaVm] FindSymbolWithoutNativeBridge not found");
        return;
    }
    HK(sym, [=](void *SharedLibrary, const std::string &symbol_name, char *shorty, JNICallType jni_call_type) -> void * {
        void *addr = SrcCall(sym, SharedLibrary, symbol_name, shorty, jni_call_type);
        console->info("FindSymbolWithoutNativeBridge( sl:{}, symbol_name:{}, shorty:{}, jni_call_type:{} [ {} ]) => {}", SharedLibrary, symbol_name, shorty, (int)jni_call_type, magic_enum::enum_name(jni_call_type), addr);
        if (addr && symbol_name == "JNI_OnLoad") {
            char buf[128];
            sprintf(buf, "xdl.xdl_showAddress(%p)", addr);
            luaL_dostring(G_LUA, buf);
        }
        return addr;
    });
    console->info("[JavaVm] register hook FindSymbolWithoutNativeBridge @ {}", sym);
}

//   void* FindSymbolWithNativeBridge(const std::string& symbol_name, const char* shorty, android::JNICallType jni_call_type)
// _ZN3art13SharedLibrary26FindSymbolWithNativeBridgeERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKc
void HK_FindSymbolWithNativeBridge() {
    void *sym = DobbySymbolResolver("libart.so", "_ZN3art13SharedLibrary26FindSymbolWithNativeBridgeERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKc");
    if (sym == nullptr) {
        console->error("[JavaVm] FindSymbolWithNativeBridge not found");
        return;
    }
    HK(sym, [=](void *SharedLibrary, const std::string &symbol_name, char *shorty, JNICallType jni_call_type) -> void * {
        void *addr = SrcCall(sym, SharedLibrary, symbol_name, shorty, jni_call_type);
        console->info("FindSymbolWithNativeBridge( sl:{}, symbol_name:{}, shorty:{}, jni_call_type:{} [ {} ]) => {}", SharedLibrary, symbol_name, shorty, (int)jni_call_type, magic_enum::enum_name(jni_call_type), addr);
        return addr;
    });
    console->info("[JavaVm] register hook FindSymbolWithNativeBridge @ {}", sym);
}

BINDFUNC(java_vm_ext) {
    luabridge::getGlobalNamespace(L)
        .beginNamespace("JavaVm")
        .addFunction("HK_LoadNativeLibrary", HK_LoadNativeLibrary)
        .addFunction("HK_FindSymbol", []() {
            // HK_FindSymbol();
            // HK_FindSymbolWithNativeBridge();
            HK_FindSymbolWithoutNativeBridge();
        })
        .endNamespace();
}