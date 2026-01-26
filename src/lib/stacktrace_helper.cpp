#include "stacktrace_helper.h"

#include "log.h"
#include "jvmti_helper.h"
#include "art/art_method.h"
#include "art/shadow_frame.h"
#include <dlfcn.h>
#include <cstring>
#include <unwind.h>
#include <cxxabi.h>

// Native 堆栈回溯结构
struct BacktraceState {
    void** current;
    void** end;
};

// unwind 回调函数
static _Unwind_Reason_Code UnwindCallback(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = reinterpret_cast<void*>(pc);
        }
    }
    return _URC_NO_REASON;
}

// 捕获 native 堆栈
static size_t CaptureNativeBacktrace(void** buffer, size_t max) {
    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(UnwindCallback, &state);
    return state.current - buffer;
}

// 打印 native 堆栈信息（使用 dladdr 解析符号并 demangle）
void PrintNativeBacktrace() {
    const int max_frames = 32;
    void* buffer[max_frames];
    
    size_t frame_count = CaptureNativeBacktrace(buffer, max_frames);
    
    loge("[!] Native Stack Trace (%zu frames):", frame_count);
    
    for (size_t i = 0; i < frame_count; i++) {
        if (buffer[i] == nullptr) {
            continue;
        }
        
        uintptr_t addr = reinterpret_cast<uintptr_t>(buffer[i]);
        
        Dl_info dl_info;
        memset(&dl_info, 0, sizeof(dl_info));
        
        if (dladdr(buffer[i], &dl_info) && dl_info.dli_fname != nullptr) {
            uintptr_t base = reinterpret_cast<uintptr_t>(dl_info.dli_fbase);
            uintptr_t offset = addr - base;
            const char* fname = dl_info.dli_fname;
            const char* symbol = dl_info.dli_sname;
            
            // 计算符号偏移
            uintptr_t symbol_offset = 0;
            if (dl_info.dli_saddr) {
                symbol_offset = addr - reinterpret_cast<uintptr_t>(dl_info.dli_saddr);
            }
            
            // Demangle C++ 符号
            if (symbol != nullptr && symbol[0] != '\0') {
                int status = -1;
                char* demangled = nullptr;
                
                try {
                    demangled = abi::__cxa_demangle(symbol, nullptr, nullptr, &status);
                } catch (...) {
                    status = -1;
                    demangled = nullptr;
                }
                
                if (status == 0 && demangled != nullptr) {
                    loge("[!]   #%02zu pc %08lx  %s (%s+%lu)", 
                         i, (unsigned long)offset, fname, demangled, (unsigned long)symbol_offset);
                    free(demangled);
                } else {
                    loge("[!]   #%02zu pc %08lx  %s (%s+%lu)", 
                         i, (unsigned long)offset, fname, symbol, (unsigned long)symbol_offset);
                }
            } else {
                loge("[!]   #%02zu pc %08lx  %s", 
                     i, (unsigned long)offset, fname);
            }
        } else {
            loge("[!]   #%02zu pc %p  (unknown)", i, buffer[i]);
        }
    }
}

// 打印 Java 堆栈信息
void PrintJavaBacktrace(jvmtiEnv* jvmti, jthread thread) {
    if (jvmti == nullptr || thread == nullptr) {
        loge("[!] Invalid parameters for Java backtrace");
        return;
    }
    
    loge("[!] Java Stack Trace:");
    
    jvmtiFrameInfo frames[32];
    jint frameCount = 0;
    jvmtiError error = jvmti->GetStackTrace(thread, 0, 32, frames, &frameCount);
    
    if (error == JVMTI_ERROR_NONE) {
        for (jint i = 0; i < frameCount; i++) {
            char* frameName = nullptr;
            char* frameSignature = nullptr;
            jclass frameClass = nullptr;
            
            error = jvmti->GetMethodName(frames[i].method, &frameName, &frameSignature, nullptr);
            if (error == JVMTI_ERROR_NONE) {
                error = jvmti->GetMethodDeclaringClass(frames[i].method, &frameClass);
                if (error == JVMTI_ERROR_NONE && frameClass != nullptr) {
                    char* frameClassSig = nullptr;
                    error = jvmti->GetClassSignature(frameClass, &frameClassSig, nullptr);
                    if (error == JVMTI_ERROR_NONE && frameClassSig != nullptr) {
                        loge("[!]   [%d] %s.%s%s (location: %lld)", 
                             i, frameClassSig, 
                             frameName ? frameName : "?",
                             frameSignature ? frameSignature : "",
                             (long long)frames[i].location);
                        jvmti->Deallocate((unsigned char*)frameClassSig);
                    }
                }
                
                if (frameName != nullptr) {
                    jvmti->Deallocate((unsigned char*)frameName);
                }
                if (frameSignature != nullptr) {
                    jvmti->Deallocate((unsigned char*)frameSignature);
                }
            }
        }
    } else {
        loge("[!] Failed to get Java stack trace, error: %d", error);
    }
}

// 用于存储找到的 MoveToExceptionHandler 帧信息
struct MoveToExceptionHandlerInfo {
    bool found;
    void* pc;
    uintptr_t thread;  // art::Thread*
    uintptr_t shadowFrame;  // art::ShadowFrame&
    uintptr_t instrumentation;  // art::instrumentation::Instrumentation const*
    uintptr_t sp;
    uintptr_t lr;
};

static MoveToExceptionHandlerInfo g_exception_handler_info = {false, nullptr, 0, 0, 0, 0, 0};

// 目标函数的 mangled 名称
static const char* TARGET_FUNC_MANGLED = "_ZN3art11interpreter22MoveToExceptionHandlerEPNS_6ThreadERNS_11ShadowFrameEPKNS_15instrumentation15InstrumentationE";

// unwind 回调函数 - 查找 MoveToExceptionHandler 并获取寄存器
// art::interpreter::MoveToExceptionHandler(art::Thread*, art::ShadowFrame&, art::instrumentation::Instrumentation const*)
static _Unwind_Reason_Code FindExceptionHandlerCallback(struct _Unwind_Context* context, void* arg) {
    MoveToExceptionHandlerInfo* info = static_cast<MoveToExceptionHandlerInfo*>(arg);
    
    // 获取当前帧的 PC
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc == 0) {
        return _URC_NO_REASON;
    }

    // 使用 dladdr 获取符号信息
    Dl_info dl_info;
    memset(&dl_info, 0, sizeof(dl_info));
    
    if (dladdr(reinterpret_cast<void*>(pc), &dl_info) && dl_info.dli_sname != nullptr) {
        // 检查是否是目标函数
        if (strcmp(dl_info.dli_sname, TARGET_FUNC_MANGLED) == 0) {
            info->found = true;
            info->pc = reinterpret_cast<void*>(pc);

            // libart.so`art::interpreter::MoveToExceptionHandler:
            //     0x74080e1ab4 <+0>:   sub    sp, sp, #0x70
            //     0x74080e1ab8 <+4>:   stp    x24, x23, [sp, #0x30]
            //     0x74080e1abc <+8>:   stp    x22, x21, [sp, #0x40]
            //     0x74080e1ac0 <+12>:  stp    x20, x19, [sp, #0x50]
            //     0x74080e1ac4 <+16>:  stp    x29, x30, [sp, #0x60]
            //     0x74080e1ac8 <+20>:  add    x29, sp, #0x60
            //     0x74080e1acc <+24>:  mrs    x23, TPIDR_EL0
            //     0x74080e1ad0 <+28>:  ldr    x8, [x23, #0x28]
            //     0x74080e1ad4 <+32>:  orr    w9, wzr, #0x2
            //     0x74080e1ad8 <+36>:  mov    x20, x2
            //     0x74080e1adc <+40>:  mov    x21, x1
            //     0x74080e1ae0 <+44>:  str    x8, [sp, #0x28]
            //     0x74080e1ae4 <+48>:  ldr    x8, [x0, #0x120]
            //     0x74080e1ae8 <+52>:  str    w9, [sp, #0x10]
            //     0x74080e1aec <+56>:  stur   xzr, [sp, #0x14]
            //     0x74080e1af0 <+60>:  str    wzr, [sp, #0x18]
            //     0x74080e1af4 <+64>:  str    x8, [sp, #0x8]
            //     0x74080e1af8 <+68>:  str    x0, [sp, #0x20]
            //     0x74080e1afc <+72>:  ldr    x8, [x0, #0xa0]
            //     0x74080e1b00 <+76>:  mov    x19, x0
            //     0x74080e1b04 <+80>:  add    x24, sp, #0x8
            //     0x74080e1b08 <+84>:  orr    w9, wzr, #0x1
            //     0x74080e1b0c <+88>:  str    x24, [x0, #0x120]
            //     0x74080e1b10 <+92>:  str    w9, [sp, #0x1c]
            //     0x74080e1b14 <+96>:  str    w8, [sp, #0x14]
            //     0x74080e1b18 <+100>: cbz    x2, 0x74080e1b4c ; <+152>
            //     0x74080e1b1c <+104>: ldrb   w9, [x20, #0xb]
            //     0x74080e1b20 <+108>: cbz    w9, 0x74080e1b4c ; <+152>
            //     0x74080e1b24 <+112>: and    x1, x8, #0xffffffff
            //     0x74080e1b28 <+116>: mov    x0, x19
            //     0x74080e1b2c <+120>: bl     0x74082fc6a4   ; art::Thread::IsExceptionThrownByCurrentMethod(art::ObjPtr<art::mirror::Throwable>) const
            //     0x74080e1b30 <+124>: tbz    w0, #0x0, 0x74080e1b4c ; <+152>
            //     0x74080e1b34 <+128>: ldr    w2, [sp, #0x14]
            //     0x74080e1b38 <+132>: mov    x0, x20
            //     0x74080e1b3c <+136>: mov    x1, x19
            //     0x74080e1b40 <+140>: bl     0x74080ab430   ; art::instrumentation::Instrumentation::ExceptionThrownEvent(art::Thread*, art::mirror::Throwable*) const
            // ->  0x74080e1b44 <+144>: ldrb   w8, [x21, #0x3c]
            //     0x74080e1b48 <+148>: tbnz   w8, #0x1, 0x74080e1c0c ; <+344>
            //     0x74080e1b4c <+152>: ldr    w8, [sp, #0x14]
            //     0x74080e1b50 <+156>: strb   wzr, [sp, #0x4]

            info->thread = _Unwind_GetGR(context, 19);  // art::Thread*
            info->shadowFrame = _Unwind_GetGR(context, 21);  // art::ShadowFrame&
            info->instrumentation = _Unwind_GetGR(context, 20);  // art::instrumentation::Instrumentation const*

            return _URC_END_OF_STACK;
        }
    }
    
    return _URC_NO_REASON;
}

// 查找并打印 MoveToExceptionHandler 函数的参数
void FindAndPrintMoveToExceptionHandlerArgs() {

    memset(&g_exception_handler_info, 0, sizeof(g_exception_handler_info));
    _Unwind_Backtrace(FindExceptionHandlerCallback, &g_exception_handler_info);

    if (g_exception_handler_info.found) {
        logw("[!] Found MoveToExceptionHandler!");
        logw("[!] MoveToExceptionHandler PC: %p", g_exception_handler_info.pc);

        // Dl_info dl_info;
        // memset(&dl_info, 0, sizeof(dl_info));
        // if (dladdr(g_exception_handler_info.pc, &dl_info) && dl_info.dli_fname != nullptr) {
        //     uintptr_t base = reinterpret_cast<uintptr_t>(dl_info.dli_fbase);
        //     uintptr_t offset = reinterpret_cast<uintptr_t>(g_exception_handler_info.pc) - base;
        //     loge("[!] Module: %s", dl_info.dli_fname);
        //     loge("[!] Base: %p, Offset: 0x%lx", dl_info.dli_fbase, (unsigned long)offset);
        // }
        //
        // loge("[!]");

        loge("[!] Function Parameters:");
        loge("[!]   art::Thread* self = 0x%lx", (unsigned long)g_exception_handler_info.thread);
        loge("[!]   art::ShadowFrame& shadow_frame = 0x%lx", (unsigned long)g_exception_handler_info.shadowFrame);
        loge("[!]   art::instrumentation::Instrumentation const* instrumentation = 0x%lx",
             (unsigned long)g_exception_handler_info.instrumentation);

        if (g_exception_handler_info.sp && g_exception_handler_info.lr) {
            loge("[!] Stack/Link Registers:");
            loge("[!]   SP = 0x%lx", (unsigned long)g_exception_handler_info.sp);
            loge("[!]   LR = 0x%lx", (unsigned long)g_exception_handler_info.lr);
        }

        // 迭代 ShadowFrame 链表
        if (g_exception_handler_info.shadowFrame != 0) {

            loge("[!] Iterating ShadowFrame chain:");
            
            auto frame = reinterpret_cast<art::ShadowFrame*>(g_exception_handler_info.shadowFrame);

            try {
                frame->Print();
                frame->GetMethod()->Print();

                frame->PrintBacktrace(2);

                // for single step test ...
                // kill -CONT pid
                // raise(SIGSTOP);

            } catch (...) {
                loge("[!] Exception while processing ShadowFrame, falling back to manual iteration");

                // 回退到手动迭代
                int frame_index = 0;
                const int max_frames = 32;
                
                while (frame != nullptr) {
                    try {
                        auto method = frame->GetMethod();
                        auto link = frame->GetLink();
                        
                        loge("[!]   Frame #%d:", frame_index);
                        loge("[!]     ShadowFrame: %p", frame);
                        loge("[!]     ArtMethod:   %p", method);
                        loge("[!]     Link:        %p", link);
                        loge("[!]     VRegs:       %u", frame->NumberOfVRegs());
                        loge("[!]     DexPC:       %u", frame->GetCurrentDexPC());

                        // 尝试获取方法信息（通过 JVMTI）
                        if (method != nullptr) {
                            jmethodID jmethod = reinterpret_cast<jmethodID>(method);

                            char* method_name = nullptr;
                            char* method_sig = nullptr;
                            jclass declaring_class = nullptr;

                            jvmtiError error = GetGlobalJvmtiEnv()->GetMethodName(jmethod, &method_name, &method_sig, nullptr);
                            if (error == JVMTI_ERROR_NONE) {
                                error = GetGlobalJvmtiEnv()->GetMethodDeclaringClass(jmethod, &declaring_class);
                                if (error == JVMTI_ERROR_NONE && declaring_class != nullptr) {
                                    char* class_sig = nullptr;
                                    error = GetGlobalJvmtiEnv()->GetClassSignature(declaring_class, &class_sig, nullptr);
                                    if (error == JVMTI_ERROR_NONE && class_sig != nullptr) {
                                        loge("[!]     Method: %s.%s%s", class_sig,
                                             method_name ? method_name : "?",
                                             method_sig ? method_sig : "");
                                        GetGlobalJvmtiEnv()->Deallocate((unsigned char*)class_sig);
                                    }
                                }

                                if (method_name != nullptr) {
                                    GetGlobalJvmtiEnv()->Deallocate((unsigned char*)method_name);
                                }
                                if (method_sig != nullptr) {
                                    GetGlobalJvmtiEnv()->Deallocate((unsigned char*)method_sig);
                                }
                            }
                        }

                        frame = link;
                        frame_index++;
                        
                    } catch (...) {
                        loge("[!]   Exception while processing frame #%d, stopping iteration", frame_index);
                        break;
                    }
                }
                
                if (frame_index >= max_frames) {
                    loge("[!]   Reached maximum frame count (%d), stopping iteration", max_frames);
                }
                
                loge("[!]   Total frames iterated: %d", frame_index);
            }
        }
    }

    loge("[!] ========================================");
}
