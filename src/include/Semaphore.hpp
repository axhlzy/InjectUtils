#pragma once

#include "log.h"
#include <semaphore.h>

class Semaphore {
private:
    Semaphore(int initialValue = 0) {
        sem_init(&g_sem, 1, initialValue);
    }

    ~Semaphore() {
        sem_destroy(&g_sem);
    }

public:
    void wait() {
        console->info("!!!SEMAPHORE_WAIT!!!");
        sem_wait(&g_sem);
    }

    void post() {
        console->info("!!!SEMAPHORE_POST!!!");
        sem_post(&g_sem);
    }

    static Semaphore *getGlobal() {
        static Semaphore instance;
        return &instance;
    }

private:
    inline static sem_t g_sem;
    Semaphore(const Semaphore &) = delete;
    Semaphore &operator=(const Semaphore &) = delete;
    Semaphore(Semaphore &&) = delete;
    Semaphore &operator=(Semaphore &&) = delete;
};

#define SEMAPHORE_POST Semaphore::getGlobal()->post();
#define SEMAPHORE_WAIT Semaphore::getGlobal()->wait();

// #include <semaphore> // C++20

// namespace Guard {
//     class SemaphoreGuard {
//     public:
//         SemaphoreGuard(std::counting_semaphore<> &sem) : semaphore(sem) {
//             semaphore.acquire();
//         }

//         ~SemaphoreGuard() {
//             semaphore.release();
//         }

//     private:
//         std::counting_semaphore<> &semaphore;
//     };
// }
