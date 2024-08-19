#pragma once

#include "main.h"

class Timer;
#define TIME_FUNCTION Timer timer(__FUNCTION__)
class ScopedLock;
class Trace;
#define TRACE_FUNCTION Trace trace(__PRETTY_FUNCTION__);

void dumpMemToFile(const void *start_addr, size_t size, const char *file_name);
char *addr2name(void *addr);
std::string hexdump(const void *data, std::size_t size = 0x20);
#define HEXLOG(ptr, len) logd("%s", hexdump(ptr, len).c_str())

void reg_crash_handler();
void showRegs(ucontext_t *ucontext);

void caps_ins(void *ptr);

#define SET_MEM_PROTECTION(address, protection) \
    mprotect((void *)((uintptr_t)(address) & ~(getpagesize() - 1)), getpagesize(), protection)

#define SET_MEM_PROTECTION_RWX(address) \
    SET_MEM_PROTECTION(address, PROT_READ | PROT_WRITE | PROT_EXEC)

#define SET_MEM_PROTECTION___(address) \
    SET_MEM_PROTECTION(address, 0)
