#include "utils.h"

using namespace std;

#include <semaphore.h>
#include "Injector/KittyInjector.hpp"
#include "KittyMemoryMgr.hpp"

KittyMemoryMgr kittyMemMgr;

void init_kittyMemMgr() {
    if (!kittyMemMgr.initialize(getpid(), EK_MEM_OP_IO, true)) {
        const char* msg = "KittyMemoryMgr initialize Error occurred )':";
        loge("%s", msg);
        console->info("{}", msg);
        return;
    }
}

#include "signal_enum.h"
#include "stacktrace.h"
#include <fmt/core.h>

// ==================== 寄存器显示 ====================

void showRegs(ucontext_t *ucontext) {
    auto ctx = ucontext->uc_mcontext;
    std::string output;

#ifdef __aarch64__
    output = fmt::format(
        "↓ ARM64 REGS ↓ \n"
        "x0: {:#020x} | x1: {:#020x} | x2: {:#020x} | x3: {:#020x}\n"
        "x4: {:#020x} | x5: {:#020x} | x6: {:#020x} | x7: {:#020x}\n"
        "x8: {:#020x} | x9: {:#020x} | x10: {:#020x} | x11: {:#020x}\n"
        "x12: {:#020x} | sp: {:#020x} | lr: {:#020x} | pc: {:#020x} \n",
        ctx.regs[0], ctx.regs[1], ctx.regs[2], ctx.regs[3],
        ctx.regs[4], ctx.regs[5], ctx.regs[6], ctx.regs[7],
        ctx.regs[8], ctx.regs[9], ctx.regs[10], ctx.regs[11],
        ctx.regs[12], ctx.sp, ctx.regs[30], ctx.pc);

#elif __arm__
    output = fmt::format(
        "↓ ARM32 REGS ↓ \n"
        "r0: {:#020x} | r1: {:#020x} | r2: {:#020x} | r3: {:#020x}\n"
        "r4: {:#020x} | r5: {:#020x} | r6: {:#020x} | r7: {:#020x}\n"
        "r8: {:#020x} | r9: {:#020x} | r10: {:#020x} | r11: {:#020x}\n"
        "r12: {:#020x} | sp: {:#020x} | lr: {:#020x} | pc: {:#020x}\n",
        ctx.arm_r0, ctx.arm_r1, ctx.arm_r2, ctx.arm_r3,
        ctx.arm_r4, ctx.arm_r5, ctx.arm_r6, ctx.arm_r7,
        ctx.arm_r8, ctx.arm_r9, ctx.arm_r10, ctx.arm_fp,
        ctx.arm_ip, ctx.arm_sp, ctx.arm_lr, ctx.arm_pc);
#endif

    console->info("{}", output);
}

// ==================== 信号处理 ====================

#include <setjmp.h>

thread_local jmp_buf recover;
thread_local void *sp = nullptr;
thread_local struct sigaction sa;

void reg_crash_handler() {
    static auto signal_handler = [](int signum, siginfo_t *info, void *context) {
        auto signStr = magic_enum::enum_name<SignalE>((SignalE)signum);
        console->error("[-] Caught signal | signum : {} [ {} ] | siginfo_t : {:p} | context : {:p}", 
                      signum, signStr, info->si_addr, context);
        
        auto ucontext = (ucontext_t *)context;
        auto ctx = ucontext->uc_mcontext;

        console->error("[-] fault_address: {:#x}", static_cast<uint64_t>(ctx.fault_address));

        showRegs(ucontext);

        sigaction(SIGSEGV, &sa, nullptr);
        longjmp(recover, 1);
    };

    sa.sa_sigaction = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);

    if (setjmp(recover) == 0) {
        asm volatile("mov %0, sp" : "=r"(sp));
        console->info("[*] Lua VM started | sp: {:p}", sp);
    } else {
        console->error("[-] Lua VM crashed and restart now | sp: {:p}", sp);
        asm volatile("mov sp, %0" : : "r"(sp));
        asm volatile("mov lr, %0" : : "r"((void *)initVM));
#ifdef __aarch64__
        asm volatile("ret");
#elif __arm__
        asm volatile("bx lr");
#endif
    }
}

// ==================== 进程信息 ====================

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

// ==================== 注入工具 ====================

KittyInjector kitInjector;
std::chrono::duration<double, std::milli> inj_ms{};

void inject(pid_t pid) {
    const string lib = getSelfPath();
    bool use_memfd = false, hide_maps = true, hide_solist = false, stopped = false;
    
    if (!kitInjector.init(pid, EK_MEM_OP_IO)) {
        console->error("KittyInjector init failed");
        return;
    }
    
    if (!kitInjector.attach()) {
        console->error("KittyInjector attach failed");
        exit(-1);
    }
    
    console->info("[*] Injecting library into process {}...", pid);
    
    kitInjector.injectLibrary(lib, RTLD_NOW | RTLD_LOCAL, use_memfd, hide_maps, hide_solist,
                              [&pid, &stopped](injected_info_t &injected) {
                                  if (injected.is_valid() && stopped) {
                                      console->info("[*] Continuing target process...");
                                      kill(pid, SIGCONT);
                                      stopped = false;
                                  }
                              });
    
    kitInjector.detach();

    console->info("[*] Waiting for server to initialize...");
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
}

// ==================== 工具函数 ====================

void set_selinux_state(bool status) {
    std::string command = status ? "setenforce 1" : "setenforce 0";
    int result = std::system(command.c_str());
    if (result != 0) {
        throw std::runtime_error("Failed to set SELinux state: " + std::to_string(result));
    }
    console->info("Successfully set SELinux to {} mode", status ? "enforcing" : "permissive");
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

    console->info("Dumped {} bytes to {}", size, file_name);
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

const char *addr2name(void *addr) {
    static const char* empty = "";
    if (addr == nullptr)
        return empty;
    
    xdl_info_t info;
    if (xdl_addr(addr, &info, NULL)) {
        const char *symbol = info.dli_sname ? info.dli_sname : "";
        string libname_string = info.dli_fname;
        string libname;
        
        if (libname_string.find("/data/app/") != string::npos) {
            libname = libname_string.substr(libname_string.find_last_of('/') + 1);
        } else {
            libname = info.dli_fname;
        }
        
        uintptr_t offset = (char *)addr - (char *)info.dli_fbase;
        return strdup((libname + " @ " + std::to_string(offset) + " | " + symbol).c_str());
    }
    return empty;
}

// ==================== 信号量封装 ====================

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