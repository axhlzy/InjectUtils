#include "utils.h"

using namespace std;

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

#include <semaphore.h>
class Semaphore {
public:
    Semaphore(int initialValue = 0) {
        sem_init(&sem, 0, initialValue);
    }

    ~Semaphore() {
        sem_destroy(&sem);
    }

    void wait() {
        sem_wait(&sem);
    }

    void signal() {
        sem_post(&sem);
    }

private:
    sem_t sem;
};

#include <semaphore> // C++20
class SemaphoreGuard {
public:
    SemaphoreGuard(std::counting_semaphore<> &sem) : semaphore(sem) {
        semaphore.acquire();
    }

    ~SemaphoreGuard() {
        semaphore.release();
    }

private:
    std::counting_semaphore<> &semaphore;
};

KittyInjector kitInjector;
std::chrono::duration<double, std::milli> inj_ms{};
void inject(pid_t pid) {
    string lib = getSelfPath();
    bool use_memfd = false, hide_maps = false, hide_solist = false, stopped = false;

    injected_info_t ret{};
    if (kitInjector.init(pid, EK_MEM_OP_IO)) {
        console->info("KittyInjector init");
        if (kitInjector.attach()) {
            console->info("KittyInjector attach");
        } else {
            console->error("KittyInjector attach failed");
            exit(-1);
        }
        auto tm_start = std::chrono::high_resolution_clock::now();

        ret = kitInjector.injectLibrary(lib, RTLD_NOW | RTLD_LOCAL, use_memfd, hide_maps, hide_solist,
                                        [&pid, &stopped](injected_info_t &injected) {
                                            if (injected.is_valid() && stopped) {
                                                console->info("[*] Continuing target process...");
                                                kill(pid, SIGCONT);
                                                stopped = false;
                                            }
                                        });

        inj_ms = std::chrono::high_resolution_clock::now() - tm_start;
        if (inj_ms.count() > 0)
            console->info("[*] Injection took {} MS.", inj_ms.count());

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