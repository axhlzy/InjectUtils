#include "utils.h"

using namespace std;

#include "Injector/KittyInjector.hpp"
#include "KittyMemoryMgr.hpp"
KittyMemoryMgr kittyMemMgr;

void init_kittyMemMgr() {
    if (!kittyMemMgr.initialize(getpid(), EK_MEM_OP_IO, true)) {
        loge("KittyMemoryMgr initialize Error occurred )':");
        console->info("KittyMemoryMgr initialize Error occurred )':");
        return;
    }
}

#include "signal_enum.h"
#include "stacktrace.h"
#include <fmt/core.h>

void showRegs(ucontext_t *ucontext) {
    auto ctx = ucontext->uc_mcontext;
    std::string output;

#ifdef __aarch64__
    output = fmt::format(
        "↓ REGS ↓ \n"
        "x0: {:#018x} | x1: {:#018x} | x2: {:#018x} | x3: {:#018x} | \n"
        "x4: {:#018x} | x5: {:#018x} | x6: {:#018x} | x7: {:#018x} | \n"
        "x8: {:#018x} | x9: {:#018x} | x10: {:#018x} | x11: {:#018x} | \n"
        "x12: {:#018x} | sp: {:#018x} | lr: {:#018x} | pc: {:#018x} \n",
        ctx.regs[0], ctx.regs[1], ctx.regs[2], ctx.regs[3],
        ctx.regs[4], ctx.regs[5], ctx.regs[6], ctx.regs[7],
        ctx.regs[8], ctx.regs[9], ctx.regs[10], ctx.regs[11],
        ctx.regs[12], ctx.sp, ctx.regs[30], ctx.pc);

#elif __arm__
    output = fmt::format(
        "↓ REGS ↓ \n"
        "r0: {:#018x} | r1: {:#018x} | r2: {:#018x} | r3: {:#018x} | \n"
        "r4: {:#018x} | r5: {:#018x} | r6: {:#018x} | r7: {:#018x} | \n"
        "r8: {:#018x} | r9: {:#018x} | r10: {:#018x} | r11: {:#018x} | \n"
        "r12: {:#018x} | sp: {:#018x} | lr: {:#018x} | pc: {:#018x} \n",
        ctx.arm_r0, ctx.arm_r1, ctx.arm_r2, ctx.arm_r3,
        ctx.arm_r4, ctx.arm_r5, ctx.arm_r6, ctx.arm_r7,
        ctx.arm_r8, ctx.arm_r9, ctx.arm_r10, ctx.arm_fp,
        ctx.arm_ip, ctx.arm_sp, ctx.arm_lr, ctx.arm_pc);
#endif

    loge("%s", output.c_str());
    console->info("{}", output);
}

#define USE_SIGNAL 0

#include <setjmp.h>
jmp_buf recover;
void *sp = nullptr;
struct sigaction sa;
void reg_crash_handler() {

#if USE_SIGNAL
    static sighandler_t segfault_handler = *[](int signum) {
        auto signStr = magic_enum::enum_name((SignalE)signum);
        loge("[-] Caught signal | signum : %d | %s \n", signum, signStr.data());
        console->error("Caught signal | signum : {} | {}", signum, signStr);
        signal(SIGSEGV, segfault_handler);
        longjmp(recover, 1);
    };
    signal(SIGSEGV, segfault_handler);
#else
    static auto signal_handler = [](int signum, siginfo_t *info, void *context) {
        auto signStr = magic_enum::enum_name<SignalE>((SignalE)signum);
        auto msg = fmt::format("[-] Caught signal | signum : {} [ {} ] | siginfo_t : {} | context : {}\n", signum, signStr, info->si_addr, context);
        loge("%s", msg.c_str());
        console->error("{}", msg);
        // extract register values
        auto ucontext = (ucontext_t *)context;
        auto ctx = ucontext->uc_mcontext;

        // fault_address
        loge("[-] fault_address: %p\n", ctx.fault_address);
        console->error("fault_address: {:p}", ctx.fault_address);
        // UnwindBacktrace();

        showRegs(ucontext);

        sigaction(SIGSEGV, &sa, nullptr);
        longjmp(recover, 1);
    };

    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
#endif

    if (setjmp(recover) == 0) {
        logd("[*] Lua VM started\n");
        // get current sp ptr
        asm volatile("mov %0, sp" : "=r"(sp));
        console->info("Lua VM started | sp: {}", sp);
    } else {
        loge("[-] Lua VM crashed and restart now\n");
        console->error("Lua VM crashed and restart now | sp: {}", sp);
        // set sp
        asm volatile("mov sp, %0" : : "r"(sp));
        // set lr = initVM
        asm volatile("mov lr, %0" : : "r"((void *)initVM));
#ifdef __aarch64__
        asm volatile("ret");
#elif __arm__
        asm volatile("bx lr");
#endif
    }
}

string getSelfPath() {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return string(buf);
    } else {
        return "";
    }
}

#include <fstream>
#include <iostream>
std::string getStat(pid_t tid) {
    std::string path = "/proc/" + std::to_string(tid) + "/stat";
    std::ifstream statFile(path);

    if (!statFile.is_open()) {
        std::cerr << "Failed to open file for process ID " << tid << std::endl;
        return "";
    }

    std::string line;
    std::getline(statFile, line);
    statFile.close();

    std::istringstream iss(line);
    long pid;         // 进程ID
    std::string comm; // 进程名称
    char state;       // 进程状态
    long ppid;        // 父进程ID
    long pgrp;        // 进程组ID

    iss >> pid >> comm >> state >> ppid >> pgrp;

    std::ostringstream result;
    result << "PID: " << pid << "\n"
           << "Command: " << comm << "\n"
           << "State: " << state << "\n"
           << "Parent PID: " << ppid << " [ " << getThreadName(ppid) << " ]" << "\n"
           << "Process Group ID: " << pgrp << "\n";

    return result.str();
}

std::string getThreadName(pid_t tid) {
    std::ifstream file(fmt::format("/proc/{}/comm", tid));
    std::string threadName;
    if (file.good()) {
        std::getline(file, threadName);
    } else {
        threadName = "unknown";
    }
    return threadName;
}

class Timer {
public:
    Timer(const std::string &funcName) : m_funcName(funcName), m_start(std::chrono::high_resolution_clock::now()) {}

    ~Timer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - m_start).count();
        std::cout << m_funcName << " took " << duration << " microseconds" << std::endl;
    }

private:
    std::string m_funcName;
    std::chrono::high_resolution_clock::time_point m_start;
};

class ScopedLock {
public:
    ScopedLock(std::mutex &m) : mutex(m) {
        mutex.lock();
    }

    ~ScopedLock() {
        mutex.unlock();
    }

private:
    std::mutex &mutex;
};

class Trace {
public:
    Trace(const std::string &funcName) : m_funcName(funcName) {
        std::cout << "Entering: " << m_funcName << std::endl;
    }

    ~Trace() {
        std::cout << "Exiting: " << m_funcName << std::endl;
    }

private:
    std::string m_funcName;
};

KittyInjector kitInjector;
std::chrono::duration<double, std::milli> inj_ms{};
void inject(pid_t pid) {
    string lib = getSelfPath();
    bool use_memfd = false, hide_maps = false, hide_solist = false, stopped = false;
    injected_info_t ret{};
    if (kitInjector.init(pid, EK_MEM_OP_IO)) {
        if (!kitInjector.attach()) {
            console->error("KittyInjector attach failed");
            exit(-1);
        }
        // auto tm_start = std::chrono::high_resolution_clock::now();
        ret = kitInjector.injectLibrary(lib, RTLD_NOW | RTLD_LOCAL, use_memfd, hide_maps, hide_solist,
                                        [&pid, &stopped](injected_info_t &injected) {
                                            if (injected.is_valid() && stopped) {
                                                console->info("[*] Continuing target process...");
                                                kill(pid, SIGCONT);
                                                stopped = false;
                                            }
                                        });

        // inj_ms = std::chrono::high_resolution_clock::now() - tm_start;
        // if (inj_ms.count() > 0)
        //     console->info("[*] Injection took {} MS.", inj_ms.count());
        kitInjector.detach();
    }
}

void checkIl2cpp() {
    std::function<bool()> const static checkIl2cppLoaded = []() -> bool {
        void *handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
        if (handle != nullptr) {
            return true;
        } else {
            return false;
        };
    };

    static std::thread t([]() {
        pthread_setname_np(pthread_self(), "dohook");
        while (true) {
            if (checkIl2cppLoaded())
                return;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    t.detach();
}

void set_selinux_state(bool status) {
    std::string command = "setenforce ";
    command += status ? "1" : "0";
    int result = std::system(command.c_str());
    if (result != 0) {
        throw std::runtime_error("Failed to set SELinux state: " + std::to_string(result));
    } else {
        std::cout << "Successfully set SELinux to " << (status ? "enforcing" : "permissive") << " mode." << std::endl;
    }
}

void dumpMemToFile(const void *start_addr, size_t size, const char *file_name) {
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        perror("fopen");
        return;
    }

    size_t written = fwrite(start_addr, 1, size, file);
    if (written != size) {
        perror("fwrite");
    }

    if (fclose(file) != 0) {
        perror("fclose");
    }

    logd("Dumped %zu bytes to %s", size, file_name);
}

string hexdump(const void *data, std::size_t size) {
    const unsigned char *bytes = static_cast<const unsigned char *>(data);

    std::ostringstream oss;

    for (std::size_t i = 0; i < size; ++i) {
        if (i % 16 == 0) {
            oss << std::setfill('0') << std::setw(8) << std::hex << i << ": ";
        }

        oss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(bytes[i]) << " ";

        if (i % 16 == 15 || i == size - 1) {
            oss << std::string(3 * (15 - i % 16), ' ') << " ";
            for (std::size_t j = i - i % 16; j <= i; ++j) {
                oss << (std::isprint(bytes[j]) ? static_cast<char>(bytes[j]) : '.');
            }
            oss << '\n';
        }
    }

    return oss.str();
}

char *addr2name(void *addr) {
    if (addr == nullptr)
        return "";
    const char *symbol = "";
    string libname = "NULL";
    uintptr_t offset = 0;
    xdl_info_t info;
    if (xdl_addr(addr, &info, NULL)) {
        symbol = info.dli_sname;
        auto libname_string = string(info.dli_fname);
        if (libname_string.find("/data/app/") != string::npos) {
            libname = libname_string.substr(libname_string.find_last_of('/') + 1).c_str();
        } else {
            libname = info.dli_fname;
        }
        offset = (char *)addr - (char *)info.dli_fbase;
        return strdup((libname + " @ " + std::to_string(offset) + " | " + symbol).c_str());
    } else {
        return "";
    }
}

class Semaphore {
private:
    sem_t sem;

public:
    Semaphore(int initialCount = 0) {
        if (sem_init(&sem, 0, initialCount) != 0) {
            throw std::runtime_error("Failed to initialize semaphore");
        }
    }

    Semaphore(const Semaphore &) = delete;
    Semaphore &operator=(const Semaphore &) = delete;

    ~Semaphore() {
        sem_destroy(&sem);
    }

    void post() {
        if (sem_post(&sem) != 0) {
            throw std::runtime_error("sem_post failed");
        }
    }

    void wait() {
        while (sem_wait(&sem) != 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("sem_wait failed");
        }
    }
};