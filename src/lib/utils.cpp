#include "utils.h"

using namespace std;

string get_self_path() {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return string(buf);
    } else {
        return "";
    }
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
