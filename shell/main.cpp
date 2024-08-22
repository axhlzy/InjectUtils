#include <android/log.h>
#include <iostream>

static const char *TAG = "SHELL";

#define logd(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define loge(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define logi(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define logw(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

#define __MAIN__ __attribute__((constructor))
#define __EXIT__ __attribute__((destructor))
#define NORETURN __attribute__((noreturn))
#define NOINLINE __attribute__((__noinline__))
#define INLINE __attribute__((__inline__))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define xASM(x) __asm __volatile__(x)
#define MACRO_HIDE_SYMBOL __attribute__((visibility("hidden")))
#define MACRO_SHOW_SYMBOL __attribute__((visibility("default")))

int main(int argc, char *argv[]) {

    logd("shell main do noting ...");

    return 0;
}

#include "tohex.h"

extern unsigned char data[];
extern unsigned int data_size;

// todo lief parse and call sym prelink
// __dl__ZN6soinfo13prelink_imageEv

__MAIN__
void init() {
    void *elf_start = data;
    void *elf_end = data + data_size;
    std::cout << "init elf_start: " << elf_start << ", elf_end: " << elf_end << std::endl;
    auto elf_reader = ShellReader(elf_start, data_size);
}