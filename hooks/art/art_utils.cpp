//
// Created by pc on 2023/8/22.
//

#include "art_utils.h"

static std::shared_ptr<spdlog::logger> logger;

/**
 * _ZN3art9ArtMethod12PrettyMethodEb -> art::ArtMethod::PrettyMethod(bool)
 *_ZN3art9ArtMethod12PrettyMethodEPS0_b -> art::ArtMethod::PrettyMethod(art::ArtMethod*, bool)
 * @param method
 * @param with_signature
 * @return
 */

// const isTiny = (str.readU8() & 1) === 0
bool isTiny(void* strPtr){
    return (((uint8_t*)strPtr)[0] & 1) == 0;
}

// const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer()
const char* getData(void* strPtr){
    if (isTiny(strPtr)){
        return (const char*)((uint8_t*)strPtr + 1);
    } else {
        return (const char*)*((uint8_t*)strPtr + 2 * sizeof(void*));
    }
}

std::string ArtUtils::PrettyMethod(ArtMethod *method, bool with_signature) {
    INIT_LOGGER();
    string ss;
    if (PrettyMethod_ptr == nullptr){
        // _ZN3art9ArtMethod12PrettyMethodEb
        void* handle = xdl_open(xorstr_("libart.so"), RTLD_LAZY);
        PrettyMethod_ptr = xdl_sym(handle, xorstr_("_ZN3art9ArtMethod12PrettyMethodEb"), nullptr);
        if (PrettyMethod_ptr == nullptr){
            LOGE("xdl_sym _ZN3art9ArtMethod12PrettyMethodEb failed");
            return "";
        }
    }

#if defined(__arm__)
//    reinterpret_cast<void (*)(void*, void*, bool)>(PrettyMethod_ptr)(tempMem, method, with_signature);
    reinterpret_cast<void (*)(void*, void*, bool)>(PrettyMethod_ptr)(&ss, method, with_signature);
#elif defined(__aarch64__)
    reinterpret_cast<void (*)(void*, bool, void*)>(PrettyMethod_ptr)(method, with_signature, &ss);
#endif
    return ss;
}
