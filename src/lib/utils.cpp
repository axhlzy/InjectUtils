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

void reg_crash_handler() {

#if USE_SIGNAL
    static sighandler_t segfault_handler = *[](int signum) {
        loge("[-] Caught signal | signum : %d \n", signum);
        console->error("Caught signal | signum : {}", signum);
        signal(SIGSEGV, segfault_handler);
        longjmp(recover, 1);
    };
    signal(SIGSEGV, segfault_handler);
#else
    static auto signal_handler = [](int signum, siginfo_t *info, void *context) {
        loge("[-] Caught signal | signum : %d | siginfo_t : %p | context : %p\n", signum, info->si_addr, context);
        console->error("Caught signal | signum : {} | siginfo_t : {} | context : {}", signum, info->si_addr, context);
        // extract register values
        ucontext_t *ucontext = (ucontext_t *)context;
        // fault_address
        loge("[-] fault_address: %p\n", ucontext->uc_mcontext.fault_address);
#ifdef __aarch64__
        loge("[-] x0: %p | x1: %p | x2: %p | x3: %p | x4: %p | x5: %p | x6: %p | x7: %p | x8: %p | x9: %p | x10: %p | x11: %p | x12: %p | sp: %p | lr: %p | pc: %p\n",
             ucontext->uc_mcontext.regs[0], ucontext->uc_mcontext.regs[1], ucontext->uc_mcontext.regs[2], ucontext->uc_mcontext.regs[3],
             ucontext->uc_mcontext.regs[4], ucontext->uc_mcontext.regs[5], ucontext->uc_mcontext.regs[6], ucontext->uc_mcontext.regs[7],
             ucontext->uc_mcontext.regs[8], ucontext->uc_mcontext.regs[9], ucontext->uc_mcontext.regs[10], ucontext->uc_mcontext.regs[11],
             ucontext->uc_mcontext.regs[12], ucontext->uc_mcontext.sp, ucontext->uc_mcontext.regs[30], ucontext->uc_mcontext.pc);
#elif __arm__
        loge("[-] r0: %p | r1: %p | r2: %p | r3: %p | r4: %p | r5: %p | r6: %p | r7: %p | r8: %p | r9: %p | r10: %p | r11: %p | r12: %p | sp: %p | lr: %p | pc: %p\n",
             ucontext->uc_mcontext.arm_r0, ucontext->uc_mcontext.arm_r1, ucontext->uc_mcontext.arm_r2, ucontext->uc_mcontext.arm_r3,
             ucontext->uc_mcontext.arm_r4, ucontext->uc_mcontext.arm_r5, ucontext->uc_mcontext.arm_r6, ucontext->uc_mcontext.arm_r7,
             ucontext->uc_mcontext.arm_r8, ucontext->uc_mcontext.arm_r9, ucontext->uc_mcontext.arm_r10, ucontext->uc_mcontext.arm_fp,
             ucontext->uc_mcontext.arm_ip, ucontext->uc_mcontext.arm_sp, ucontext->uc_mcontext.arm_lr, ucontext->uc_mcontext.arm_pc);
#endif
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