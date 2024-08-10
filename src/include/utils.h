#pragma once

#include "main.h"

class Timer;
#define TIME_FUNCTION Timer timer(__FUNCTION__)
class ScopedLock;
class Trace;
#define TRACE_FUNCTION Trace trace(__PRETTY_FUNCTION__);
class Semaphore;
class SemaphoreGuard;

#define USE_SIGNAL 0

#include <setjmp.h>
static jmp_buf recover;
static void *sp = nullptr;
static struct sigaction sa;

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
        logd("[*] Lua VM started\n"); // android_logcat
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

KittyMemoryMgr kittyMemMgr;
void init_kittyMemMgr() {
    if (!kittyMemMgr.initialize(getpid(), EK_MEM_OP_IO, true)) {
        loge("KittyMemoryMgr initialize Error occurred )':");
        console->info("KittyMemoryMgr initialize Error occurred )':");
        return;
    }
}