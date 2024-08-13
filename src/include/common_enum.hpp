#pragma once

#include <string>

enum class Protection : uint32_t {
    _PROT_READ = 0x1,             // 可读权限
    _PROT_WRITE = 0x2,            // 可写权限
    _PROT_EXEC = 0x4,             // 可执行权限
    _PROT_SEM = 0x8,              // 信号量的权限
    _PROT_NONE = 0x0,             // 无权限
    _PROT_GROWSDOWN = 0x01000000, // 向下增长，特定情况使用
    _PROT_GROWSUP = 0x02000000    // 向上增长，特定情况使用
};

enum class _SIGnal {
    _SIGHUP = 1,
    _SIGINT = 2,
    _SIGQUIT = 3,
    _SIGILL = 4,
    _SIGTRAP = 5,
    _SIGABRT = 6,
    _SIGIOT = 6, // _SIGIOT 和 _SIGABRT 具有相同的值
    _SIGBUS = 7,
    _SIGFPE = 8,
    _SIGKILL = 9,
    _SIGUSR1 = 10,
    _SIGSEGV = 11,
    _SIGUSR2 = 12,
    _SIGPIPE = 13,
    _SIGALRM = 14,
    _SIGTERM = 15,
    _SIGSTKFLT = 16,
    _SIGCHLD = 17,
    _SIGCONT = 18,
    _SIGSTOP = 19,
    _SIGTSTP = 20,
    _SIGTTIN = 21,
    _SIGTTOU = 22,
    _SIGURG = 23,
    _SIGXCPU = 24,
    _SIGXFSZ = 25,
    _SIGVTALRM = 26,
    _SIGPROF = 27,
    _SIGWINCH = 28,
    _SIGIO = 29,
    _SIGPOLL = _SIGIO, // 群体共用值
    _SIGPWR = 30,
    _SIGSYS = 31,
    _SIGUNUSED = 31 // _SIGUNUSED 扩展为 _SIGSYS
};

inline bool hasProtection(uint32_t currentProtection, Protection checkProtection) {
    return currentProtection & static_cast<uint32_t>(checkProtection);
}

inline const std::string getProtectionDetails(uint32_t prot) {
    std::string result;
    result.clear();

    if (hasProtection(prot, Protection::_PROT_READ)) {
        result += "PROT_READ ";
    }
    if (hasProtection(prot, Protection::_PROT_WRITE)) {
        result += "PROT_WRITE ";
    }
    if (hasProtection(prot, Protection::_PROT_EXEC)) {
        result += "PROT_EXEC ";
    }
    if (hasProtection(prot, Protection::_PROT_SEM)) {
        result += "PROT_SEM ";
    }
    if (hasProtection(prot, Protection::_PROT_NONE)) {
        result += "PROT_NONE ";
    }
    if (hasProtection(prot, Protection::_PROT_GROWSDOWN)) {
        result += "PROT_GROWSDOWN ";
    }
    if (hasProtection(prot, Protection::_PROT_GROWSUP)) {
        result += "PROT_GROWSUP ";
    }
    return result;
}

enum class DynamicTag : u_int64_t {
    _DT_NULL = 0,
    _DT_NEEDED = 1,
    _DT_PLTRELSZ = 2,
    _DT_PLTGOT = 3,
    _DT_HASH = 4,
    _DT_STRTAB = 5,
    _DT_SYMTAB = 6,
    _DT_RELA = 7,
    _DT_RELASZ = 8,
    _DT_RELAENT = 9,
    _DT_STRSZ = 10,
    _DT_SYMENT = 11,
    _DT_INIT = 12,
    _DT_FINI = 13,
    _DT_SONAME = 14,
    _DT_RPATH = 15,
    _DT_SYMBOLIC = 16,
    _DT_REL = 17,
    _DT_RELSZ = 18,
    _DT_RELENT = 19,
    _DT_PLTREL = 20,
    _DT_DEBUG = 21,
    _DT_TEXTREL = 22,
    _DT_JMPREL = 23,
    _DT_BIND_NOW = 24,
    _DT_INIT_ARRAY = 25,
    _DT_FINI_ARRAY = 26,
    _DT_INIT_ARRAYSZ = 27,
    _DT_FINI_ARRAYSZ = 28,
    _DT_ENCODING = 32,
    _OLD__DT_LOOS = 0x60000000,
    _DT_LOOS = 0x6000000d,
    _DT_HIOS = 0x6ffff000,
    _DT_VALRNGLO = 0x6ffffd00,
    _DT_VALRNGHI = 0x6ffffdff,
    _DT_ADDRRNGLO = 0x6ffffe00,
    _DT_ADDRRNGHI = 0x6ffffeff,
    _DT_VERSYM = 0x6ffffff0,
    _DT_RELACOUNT = 0x6ffffff9,
    _DT_RELCOUNT = 0x6ffffffa,
    _DT_FLAGS_1 = 0x6ffffffb,
    _DT_VERDEF = 0x6ffffffc,
    _DT_VERDEFNUM = 0x6ffffffd,
    _DT_VERNEED = 0x6ffffffe,
    _DT_VERNEEDNUM = 0x6fffffff,
    _OLD_DT_HIOS = 0x6fffffff,
    _DT_LOPROC = 0x70000000,
    _DT_HIPROC = 0x7fffffff
};

enum class ProgramHeaderType : u_int64_t {
    _PT_NULL = 0,
    _PT_LOAD = 1,
    _PT_DYNAMIC = 2,
    _PT_INTERP = 3,
    _PT_NOTE = 4,
    _PT_SHLIB = 5,
    _PT_PHDR = 6,
    _PT_TLS = 7,
    _PT_LOOS = 0x60000000,
    _PT_HIOS = 0x6fffffff,
    _PT_LOPROC = 0x70000000,
    _PT_HIPROC = 0x7fffffff,
    _PT_GNU_EH_FRAME = 0x6474e550,
    _PT_GNU_PROPERTY = 0x6474e553,
    // _PT_GNU_STACK = (PT_LOOS + 0x474e551) // (PT_LOOS + 0x474e551) => _PT_LOOS + 0x474e551
};

enum class ElfType {
    _ET_NONE = 0,
    _ET_REL = 1,
    _ET_EXEC = 2,
    _ET_DYN = 3,
    _ET_CORE = 4
};

enum class ST_SymbolType : int {
    _STT_NOTYPE = 0,
    _STT_OBJECT = 1,
    _STT_FUNC = 2,
    _STT_SECTION = 3,
    _STT_FILE = 4,
    _STT_COMMON = 5,
    _STT_TLS = 6
};

enum class ST_BindingType : int {
    _STB_LOCAL = 0,
    _STB_GLOBAL = 1,
    _STB_WEAK = 2
};

enum class FileAccessFlag : int {
    _AT_FDCWD = -100,
    _AT_SYMLINK_NOFOLLOW = 0x100,
    _AT_EACCESS = 0x200,
    _AT_REMOVEDIR = 0x200,
    _AT_SYMLINK_FOLLOW = 0x400,
    _AT_NO_AUTOMOUNT = 0x800,
    _AT_EMPTY_PATH = 0x1000,
    _AT_STATX_SYNC_TYPE = 0x6000,
    _AT_STATX_SYNC_AS_STAT = 0x0000,
    _AT_STATX_FORCE_SYNC = 0x2000,
    _AT_STATX_DONT_SYNC = 0x4000,
    _AT_RECURSIVE = 0x8000
};

enum class DirectoryNotifyFlag : long long {
    _DN_ACCESS = 0x00000001,
    _DN_MODIFY = 0x00000002,
    _DN_CREATE = 0x00000004,
    _DN_DELETE = 0x00000008,
    _DN_RENAME = 0x00000010,
    _DN_ATTRIB = 0x00000020,
    _DN_MULTISHOT = 0x80000000
};