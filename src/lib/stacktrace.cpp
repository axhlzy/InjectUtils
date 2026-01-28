#include "stacktrace.h"
#include "log.h"
#include "jvmti_helper.h"
#include "art/art_method.h"
#include "art/shadow_frame.h"
#include "xdl.h"
#include "boost/core/demangle.hpp"

#include <dlfcn.h>
#include <cstring>
#include <unwind.h>
#include <cxxabi.h>
#include <android/log.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <algorithm>

std::vector<MemRegion> mem_regions;

void read_maps() {
    std::ifstream maps_file("/proc/self/maps");
    if (!maps_file.is_open()) {
        std::cerr << "Failed to open /proc/self/maps" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        std::istringstream line_stream(line);

        std::string addr_info, perms, offset, device, inode, pathname;
        line_stream >> addr_info >> perms >> offset >> device >> inode;
        std::getline(line_stream, pathname);

        std::replace(pathname.begin(), pathname.end(), ' ', '\0');
        if (pathname == "") {
            pathname = "UNKNOW";
        }

        uintptr_t start, end;
        char dash;
        std::istringstream addr_stream(addr_info);
        addr_stream >> std::hex >> start >> dash >> std::hex >> end;

        uintptr_t offset_value;
        std::istringstream offset_stream(offset);
        offset_stream >> std::hex >> offset_value;

        MemRegion region = {start, end, offset_value, pathname, pathname.substr(pathname.find_last_of('/') + 1)};
        mem_regions.push_back(region);
    }

    maps_file.close();
}

// Function to find memory region containing a specific address
const MemRegion *find_mem_region(uintptr_t addr) {
    for (const auto &region : mem_regions) {
        if (addr >= region.start && addr < region.end) {
            return &region;
        }
    }
    return nullptr;
}

// Function to get address information
std::string get_addr_info(uintptr_t addr) {
    xdl_info_t info;
    if (xdl_addr((void *)addr, &info, NULL)) {
        // 0x123 @ libname.so | symbol
        return std::string(info.dli_sname) + " @ " + std::to_string(addr - (uintptr_t)info.dli_fbase) + " | " + std::string(info.dli_fname);
    } else {
        // to hex string
        std::stringstream ss;
        ss << std::hex << addr;
        return ss.str();
    }
}

// ==================== Native 堆栈回溯 ====================

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

// ==================== ShadowFrame 分析 ====================

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
static _Unwind_Reason_Code FindExceptionHandlerCallback(struct _Unwind_Context* context, void* arg) {
    MoveToExceptionHandlerInfo* info = static_cast<MoveToExceptionHandlerInfo*>(arg);
    
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc == 0) {
        return _URC_NO_REASON;
    }

    Dl_info dl_info;
    memset(&dl_info, 0, sizeof(dl_info));
    
    if (dladdr(reinterpret_cast<void*>(pc), &dl_info) && dl_info.dli_sname != nullptr) {
        if (strcmp(dl_info.dli_sname, TARGET_FUNC_MANGLED) == 0) {
            info->found = true;
            info->pc = reinterpret_cast<void*>(pc);
            info->thread = _Unwind_GetGR(context, 19);
            info->shadowFrame = _Unwind_GetGR(context, 21);
            info->instrumentation = _Unwind_GetGR(context, 20);
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

        if (g_exception_handler_info.shadowFrame != 0) {
            loge("[!] Iterating ShadowFrame chain:");
            
            auto frame = reinterpret_cast<art::ShadowFrame*>(g_exception_handler_info.shadowFrame);

            try {
                frame->Print();
                frame->GetMethod()->Print();
                frame->PrintBacktrace(2);
            } catch (...) {
                loge("[!] Exception while processing ShadowFrame, falling back to manual iteration");

                int frame_index = 0;
                const int max_frames = 32;
                
                while (frame != nullptr && frame_index < max_frames) {
                    try {
                        auto method = frame->GetMethod();
                        auto link = frame->GetLink();
                        
                        loge("[!]   Frame #%d:", frame_index);
                        loge("[!]     ShadowFrame: %p", frame);
                        loge("[!]     ArtMethod:   %p", method);
                        loge("[!]     Link:        %p", link);
                        loge("[!]     VRegs:       %u", frame->NumberOfVRegs());
                        loge("[!]     DexPC:       %u", frame->GetCurrentDexPC());

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

// ==================== 通用堆栈工具 ====================

inline bool readMemory(uintptr_t address, uintptr_t &value) {
    value = *reinterpret_cast<uintptr_t *>(address);
    return true;
}

std::vector<uintptr_t> stacktrace(rword pc, rword lr, rword fp, rword sp) {
    std::vector<uintptr_t> stack_arr;

    stack_arr.push_back(pc);
    stack_arr.push_back(lr);

    while (fp) {
        uintptr_t next_fp = 0;
        uintptr_t return_addr = 0;

        if (!readMemory(fp, next_fp)) {
            break;
        }

        if (!readMemory(fp + sizeof(uintptr_t), return_addr)) {
            break;
        }

        if (return_addr != 0)
            stack_arr.push_back(return_addr);

        fp = next_fp;
    }

    return stack_arr;
}

void printBacktrace(vector<void *> backtraceArray) {
#ifndef DEBUG_PROJECT
    return;
#endif
    for (size_t idx = 0; idx < backtraceArray.size(); ++idx) {
        const void *addr = backtraceArray[idx];
        const char *symbol = "";
        string libname;
        uintptr_t offset = 0;

        void *cache = NULL;
        xdl_info_t info;
        if (xdl_addr((void *)addr, &info, &cache)) {
            symbol = info.dli_sname;
            auto libname_string = string(info.dli_fname);
            if (libname_string.find("/data/app/") != string::npos) {
                libname = libname_string.substr(libname_string.find_last_of('/') + 1).c_str();
            } else {
                libname = info.dli_fname;
            }
            offset = (char *)addr - (char *)info.dli_fbase;
        }
        xdl_addr_clean(&cache);

        string decode;
        if (symbol != nullptr && strlen(symbol) != 0 && symbol != string("(null)")) {
            decode.insert(0, " <- ");
            decode.insert(0, boost::core::demangle(symbol));
            decode.append(symbol);
        }

        __android_log_print(ANDROID_LOG_INFO, "Backtrace", "| #%02zu: %p { %p @ %s } %s",
                            idx, addr, reinterpret_cast<void *>(offset), libname.c_str(), decode.c_str());
    }
}

// ==================== UnwindBacktrace (调试用) ====================

void UnwindBacktrace(const string &lastFunctionName, bool printRegisters) {
#ifndef DEBUG_PROJECT
    return;
#endif

#define BACKTRACE_SIZE 100

    static bool printRegisters_ = printRegisters;

    static auto printRegs = [=](struct _Unwind_Context *context) {
        stringstream ss;
        if (printRegisters_) {
#ifdef __arm__
            // ARM32 callee-saved registers are: r4-r8, r10, r11 and r13
            int registers[] = {4, 5, 6, 7, 8, 10, 11, 13};
#elif defined(__aarch64__)
            // ARM64 callee-saved registers are: x19-x30
            int registers[] = {19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
#endif
            for (int reg : registers) {
                uintptr_t value = _Unwind_GetGR(context, reg);
#ifdef __arm__
                ss << "r" << to_string(reg) << ":0x" << hex << value << " ";
#elif defined(__aarch64__)
                ss << "x" << to_string(reg) << ":0x" << hex << value << " ";
#endif
            }
        }
        return ss.str();
    };

    static auto unwindCallback = +[](struct _Unwind_Context *context, void *arg) -> _Unwind_Reason_Code {
        struct BacktraceState {
            void **current;
            void **end;
        };

        BacktraceState *state = static_cast<BacktraceState *>(arg);
        uintptr_t pc = _Unwind_GetIP(context);
        if (pc) {
            auto ret = printRegs(context);
            if (ret.length() > 0) {
                __android_log_print(ANDROID_LOG_ERROR, "Backtrace", "%s", ret.c_str());
            }
            if (state->current == state->end) {
                return _URC_END_OF_STACK;
            } else {
                *state->current++ = reinterpret_cast<void *>(pc);
            }
        }
        return _URC_NO_REASON;
    };

    static auto captureBacktrace = [&](void **buffer, size_t max) -> size_t {
        struct BacktraceState {
            void **current;
            void **end;
        } state = {buffer, buffer + max};

        _Unwind_Backtrace(unwindCallback, &state);

        return state.current - buffer;
    };

    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "┍ captureBacktrace -> { %s }", lastFunctionName.c_str());
    void *buffer[BACKTRACE_SIZE];
    
    vector<void *> backtraceArray(buffer, buffer + captureBacktrace(buffer, BACKTRACE_SIZE));
    printBacktrace(backtraceArray);
    
    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "└ captureBacktrace end");
}
