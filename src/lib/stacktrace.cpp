#include "stacktrace.h"
#include "xdl.h"

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

inline bool readMemory(uintptr_t address, uintptr_t &value) {
    value = *reinterpret_cast<uintptr_t *>(address);
    return true;
}

std::vector<uintptr_t> stacktrace(rword pc, rword lr, rword fp, rword sp) {
    std::vector<uintptr_t> stack_arr;

    // 添加初始的 PC 和 LR
    stack_arr.push_back(pc);
    stack_arr.push_back(lr);

    // 遍历栈帧
    while (fp) {
        uintptr_t next_fp = 0;
        uintptr_t return_addr = 0;

        // 读取下一帧的帧指针
        if (!readMemory(fp, next_fp)) {
            break;
        }

        // 读取返回地址
        if (!readMemory(fp + sizeof(uintptr_t), return_addr)) {
            break;
        }

        if (return_addr != 0)
            stack_arr.push_back(return_addr);

        // 更新 fp
        fp = next_fp;
    }

    return stack_arr;
}

// int main() {
//     // Example usage of the functions
//     read_maps();

//     // The below addresses would be specific to your context
//     unsigned long pc = 0x12345678;
//     unsigned long lr = 0x87654321;
//     unsigned long fp = 0x0ABCDEF0;
//     unsigned long sp = 0x12345600;

//     auto trace = stacktrace(pc, lr, fp, sp);
//     for (const auto &addr : trace) {
//         std::cout << get_addr_info(addr) << std::endl;
//     }
//     return 0;
// }

#include "xdl.h"
#include <android/log.h>
#include <boost/core/demangle.hpp>
#include <boost/stacktrace.hpp>
#include <boost/type_index.hpp>
#include <dlfcn.h>
#include <unwind.h>

// Gum::ReturnAddressArray ra;
// auto bk = Gum::Backtracer_make_accurate();
// bk->generate(context->get_cpu_context(), ra);
// vector<void*> vec;
// for (int i=0 ; i<ra.len ; i++) vec.push_back(ra.items[i]);
// Utils::printBacktrace(vec);

void dumpBacktrace(void **buffer, size_t count) {
#ifndef DEBUG_PROJECT
    return;
#endif
    vector<void *> backtraceArray(buffer, buffer + count);
    printBacktrace(backtraceArray);
};

#define USE_BOOST_Backtrace 0

void UnwindBacktrace(const string &lastFunctionName, bool printRegisters) {
#ifndef DEBUG_PROJECT
    return;
#endif

#if USE_BOOST_Backtrace

    //    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "┍ captureBacktrace -> { %s }", lastFunctionName.c_str());
    //        stringstream os;
    //    os << boost::stacktrace::stacktrace();
    //    __android_log_print(ANDROID_LOG_INFO, "ZZZ", "%s", os.str().c_str());
    //    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "└ captureBacktrace end");

    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "┍ captureBacktrace -> { %s }", lastFunctionName.c_str());
    boost::stacktrace::stacktrace trace;
    for (const auto &frame : trace) {
        std::stringstream os;
        os << frame << " (" << frame.source_file() << ":" << frame.source_line() << ")";
        __android_log_print(ANDROID_LOG_INFO, "ZZZ", "%s", os.str().c_str());
    }
    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "└ captureBacktrace end");

#else

#ifdef DEBUG_PROJECT
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
    dumpBacktrace(buffer, captureBacktrace(buffer, BACKTRACE_SIZE));
    __android_log_print(ANDROID_LOG_INFO, "Backtrace", "└ captureBacktrace end");
#endif

#endif
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
            // boost::typeindex::type_id_runtime(addr).pretty_name() // type_id_runtime() 函数接受一个对象的地址作为参数，并返回一个类型标识符对象。pretty_name() 方法用于获取该类型标识符对象的字符串表示形式，即该类型的名称
            // decode.append(abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr))
            decode.insert(0, boost::core::demangle(symbol));
            decode.append(symbol);
        }

        __android_log_print(ANDROID_LOG_INFO, "Backtrace", "| #%02zu: %p { %p @ %s } %s",
                            idx, addr, reinterpret_cast<void *>(offset), libname.c_str(), decode.c_str());
    }
};