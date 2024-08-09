//
// Created by pc on 2023/8/9.
//

#ifndef IL2CPPHOOKER_HOOKTEMPLATE_H
#define IL2CPPHOOKER_HOOKTEMPLATE_H

#include <string>
#include "frida-gum.h"

//#ifdef __aarch64__
//using instrument_callback = void (*)(void *address, GumArm64CpuContext *ctx);
//#elif __arm__
//using instrument_callback = void (*)(void *address, GumArmCpuContext *ctx);
//#endif
//
//class HookTemplate {
//
//public:
//
//    virtual void Init() = 0;
//
//    virtual void* Hook(void *function_address, void *replacement_address, void **original_function, void *replacement_data = nullptr) = 0;
//
//    virtual void* Hook(const char *lib_name, const char *sym_name, void *replacement_address, void **original_function) = 0;
//
//    virtual void* Inline(void *function_address, instrument_callback callback) = 0;
//
//    virtual void UnHook(void *function_address) = 0;
//
//    virtual std::string getVersion() = 0;
//};

#endif //IL2CPPHOOKER_HOOKTEMPLATE_H
