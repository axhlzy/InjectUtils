#ifndef ANTISDK_SYSCALLS_H
#define ANTISDK_SYSCALLS_H

#include <asm-generic/unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "syscall_arch.h"

#define UNEXPORT __attribute__((visibility("hidden")))
#define INIT_ARRAY UNEXPORT __attribute__((constructor))
#define NAKED __attribute__((naked))
#define INLINE __attribute__((always_inline))

UNEXPORT INLINE static inline int my_openat(int __dir_fd, const void *__path, int __flags, int __mode) {
    return (int)__syscall4(__NR_openat, __dir_fd, (long)__path, __flags, __mode);
}

UNEXPORT INLINE static inline ssize_t my_read(int __fd, void *__buf, size_t __count) {
    return __syscall3(__NR_read, __fd, (long)__buf, (long)__count);
}

UNEXPORT INLINE static inline off_t my_lseek(int __fd, off_t __offset, int __whence) {
    return __syscall3(__NR_lseek, __fd, __offset, __whence);
}

UNEXPORT INLINE static inline int my_close(int __fd) {
    return (int)__syscall1(__NR_close, __fd);
}

UNEXPORT INLINE static inline int my_nanosleep(const struct timespec *__request, struct timespec *__remainder) {
    return (int)__syscall2(__NR_nanosleep, (long)__request, (long)__remainder);
}

UNEXPORT INLINE static inline ssize_t my_readlinkat(const char *__path, char *__buf, size_t __buf_size) {
    return __syscall4(__NR_readlinkat, AT_FDCWD, (long)__path, (long)__buf, (long)__buf_size);
}

UNEXPORT INLINE static inline int my_tgkill(int __tgid, int __tid, int __signal) {
    return (int)__syscall3(__NR_tgkill, __tgid, __tid, __signal);
}

UNEXPORT INLINE static inline void my_exit(int __status) {
    __syscall1(__NR_exit, __status);
}

UNEXPORT INLINE static inline long my_kill(int __pid, int __sig) {
    return (int)__syscall2(__NR_kill, __pid, __sig);
}

UNEXPORT INLINE static inline int my_stat(const char *path, struct stat *sb) {
    return (int)__syscall4(79, AT_FDCWD, (long)path, (long)&sb, 0);
}

UNEXPORT INLINE static inline int my_lstat(const char *path, struct stat *sb) {
    return (int)__syscall4(79, AT_FDCWD, (long)path, (long)sb, AT_SYMLINK_NOFOLLOW);
}

#include <string>

class Syscall {
public:
    /**
     * svc读取文件
     * @param filePath
     * @return
     */
    static std::string readFile(const char *filePath);
    static int my_openat(int __dir_fd, const void *__path, int __flags, int __mode);
    static ssize_t my_read(int __fd, void *__buf, size_t __count);
    static int my_close(int __fd);
    static std::string read_file_for_svc(const char *path);
    static off_t my_lseek(int __fd, off_t __offset, int __whence);
    /**
     * kill函数
     * @param pid
     * @param sig
     */
    static void kill(int pid, int sig);

    /**
     * 检查路径或文件是否存在
     * @param path
     * @return
     */
    static bool check_file_or_dir_exists(char *path);

    static long readlink(const char *path, char *const buf, size_t size);

    static void socket();
    static void connect();
};

#endif