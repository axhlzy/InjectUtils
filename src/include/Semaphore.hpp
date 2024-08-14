#pragma once

#include "log.h"
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
        console->info("!!!SEMAPHORE_WAIT!!!");
        sem_wait(&sem);
    }

    void post() {
        console->info("!!!SEMAPHORE_POST!!!");
        sem_post(&sem);
    }

    static Semaphore *getGlobal() {
        static Semaphore instance(0);
        return &instance;
    }

private:
    sem_t sem;

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
