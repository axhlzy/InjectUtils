#pragma once

#include "main.h"

class Timer;
#define TIME_FUNCTION Timer timer(__FUNCTION__)
class ScopedLock;
class Trace;
#define TRACE_FUNCTION Trace trace(__PRETTY_FUNCTION__);

#define USE_SIGNAL 0

#include <setjmp.h>
static jmp_buf recover;
static void *sp = nullptr;
static struct sigaction sa;

void reg_crash_handler();

void init_kittyMemMgr();

void dumpMemToFile(const void *start_addr, size_t size, const char *file_name);
char *addr2name(void *addr);
std::string hexdump(const void *data, std::size_t size = 0x20);
#define HEXLOG(ptr, len) logd("%s", hexdump(ptr, len).c_str())

#define SET_MEM_PROTECTION(address) \
    mprotect((void *)((uintptr_t)(address) & ~(getpagesize() - 1)), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC)
