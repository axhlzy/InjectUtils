#if !defined(LOG_STACKTRACE_H)
#define LOG_STACKTRACE_H

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "QBDI/State.h"

using namespace std;
using namespace QBDI;

struct MemRegion {
    unsigned long start;
    unsigned long end;
    unsigned long offset;
    std::string path;
    std::string name;
};

std::vector<uintptr_t> stacktrace(rword pc, rword lr, rword fp, rword sp);

std::string get_addr_info(unsigned long addr);

__attribute__((visibility("hidden")))
__attribute__((always_inline)) void
UnwindBacktrace(const string &lastFunctionName = "...", bool printRegisters = false);

void printBacktrace(vector<void *> backtraceArray);

void dumpBacktrace(void **buffer, size_t count);

#endif