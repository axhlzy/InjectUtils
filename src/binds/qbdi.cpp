#include "QBDI.h"
#include "bindings.h"
#include "config.h"
#include "linker_soinfo.h"
#include "stacktrace.h"

using namespace QBDI;

using initArrayFunction = void (*)();

class QBDI_TRACE {

private:
    inline static uintptr_t _libBase; // 全局
    uint8_t *_fakestack = nullptr;
    std::unique_ptr<QBDI::VM> _vm;
    rword _retVal;
    rword gfp = 0;
    const soinfo *_soinfo;

public:
    QBDI_TRACE() : _vm(std::make_unique<QBDI::VM>()) {
    }

    QBDI_TRACE(PTR info) {
        QBDI_TRACE(reinterpret_cast<const soinfo *>(info));
    }

    QBDI_TRACE(const soinfo *info) : _soinfo(info) {
        _libBase = info->base;
    }

    ~QBDI_TRACE() {
        QBDI::alignedFree(_fakestack);
    }

    void setBase(uintptr_t base) {
        _libBase = base;
    }

    void trace_dynstr() {
        // .dynstr
        const char *str_start = reinterpret_cast<const char *>(_soinfo->strtab_);
        const char *str_end = nullptr;

        for (auto dyn = _soinfo->dynamic; dyn->d_tag != DT_NULL; ++dyn) {
            if (dyn->d_tag == DT_STRSZ) {
                str_end = str_start + dyn->d_un.d_val;
                break;
            }
        }

        auto start = reinterpret_cast<QBDI::rword>(str_start);
        auto end = reinterpret_cast<QBDI::rword>(str_end);

        _vm->addMemRangeCB(start, end, MemoryAccessType::MEMORY_WRITE, [](QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
            console->info("MemRangeCB dynstr: {:p}", (gprState->pc - _libBase));
            const QBDI::InstAnalysis *instAnalysis = vm->getCachedInstAnalysis(gprState->pc);
            console->info("\t{:p} {}", instAnalysis->address, instAnalysis->disassembly);
            return QBDI::VMAction::CONTINUE; }, NULL);

        console->info("REG {} [ {:p} ~ {:p} ]", __FUNCTION__, start, end);
    }

    void trace_dynsym() {
        // .dynsym
        const char *str_start = reinterpret_cast<const char *>(_soinfo->strtab_);
        const ElfW(Sym) *symtab_start = reinterpret_cast<const ElfW(Sym) *>(_soinfo->symtab_);
        const char *symtab_end = reinterpret_cast<const char *>(str_start);

        auto start = reinterpret_cast<QBDI::rword>(symtab_start);
        auto end = reinterpret_cast<QBDI::rword>(symtab_end);

        _vm->addMemRangeCB(start, end, MemoryAccessType::MEMORY_WRITE, [](QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
            console->info("MemRangeCB dynsym: {:p}", (gprState->pc - _libBase));
            const QBDI::InstAnalysis *instAnalysis = vm->getCachedInstAnalysis(gprState->pc);
            console->info("\t{:p} %s", instAnalysis->address, instAnalysis->disassembly);
        return QBDI::VMAction::CONTINUE; }, NULL);

        console->info("REG {} [ {:p} ~ {:p} ]", __FUNCTION__, start, end);
    }

    void trace_got() {

        void *got_start = nullptr;
        void *got_end = nullptr;
        for (auto dyn = _soinfo->dynamic; dyn->d_tag != DT_NULL; ++dyn) {
            if (dyn->d_tag == DT_PLTGOT) {
                got_start = reinterpret_cast<void *>(dyn->d_un.d_ptr + _soinfo->base);
            }
            if (dyn->d_tag == DT_PLTRELSZ) {
                got_end = reinterpret_cast<void *>(dyn->d_un.d_ptr + (uintptr_t)got_start);
            }
        }

        // .got              PROGBITS        00000000005bdc30 5bcc30 0063d0
        auto start = reinterpret_cast<QBDI::rword>(got_start);
        auto end = reinterpret_cast<QBDI::rword>(got_end);

        _vm->addMemRangeCB(start, end, MemoryAccessType::MEMORY_WRITE, [](QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
            console->info("MemRangeCB got: {:p}", (gprState->pc - _libBase));
            const QBDI::InstAnalysis *instAnalysis = vm->getCachedInstAnalysis(gprState->pc);
            console->info("\t{:p} %s", instAnalysis->address, instAnalysis->disassembly);
            UnwindBacktrace();
        return QBDI::VMAction::CONTINUE; }, NULL);
        console->info("REG {} [ {:p} ~ {:p} ]", __FUNCTION__, start, end);
    }

    void trace_code() {
        _vm->addCodeCB(QBDI::PREINST, [](QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
            const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis();
            if (string(instAnalysis->disassembly).find("svc") != std::string::npos) {
                // raise(SIGSTOP);
                auto last = vm->getCachedInstAnalysis(gprState->pc - 4);
                // mov	x8, #63
                const string disstr = last->disassembly;
                int svc_code = stoi(disstr.substr(disstr.find("#") + 1, disstr.length()));

                handle_svc((SYSCALL)svc_code, gprState);

                const auto svc = magic_enum::enum_name<SYSCALL>((SYSCALL)svc_code);
                // 0x79fef93400 	mov	x8, #63 [ 63 | _NR_read ]
                console->info("\t{:p} %s [ %d | %s ]", last->address, last->disassembly, svc_code, svc.data());
                // 0x79fef93404 	svc	#0
                console->info("\t{:p} %s", instAnalysis->address, instAnalysis->disassembly);

                // UnwindBacktrace();
        }
        return QBDI::VMAction::CONTINUE; }, NULL);
        console->info("REG {}", __FUNCTION__);
    }

    void printStartStatus(QBDI::GPRState *state) {
#if defined(__aarch64__)
        gfp = state->x29;
        console->info("vmCall State: fp:{:p} | lr:{:p} | sp:{:p} | pc:{:p}", state->x29, state->lr, state->sp, state->pc);
#elif defined(__arm__)
        gfp = state->r7;
        console->info("vmCall State: fp:{:p} | lr:{:p} | sp:{:p} | pc:{:p}", state->r7, state->lr, state->sp, state->pc);
#else
#error "Unsupported architecture"
#endif
        console->info("libBase {:p}", _libBase);
    }

    void vmCall(QBDI::rword funcPtr) {
        QBDI::GPRState *state = _vm->getGPRState();
        QBDI::allocateVirtualStack(state, Config::VIRTUAL_STACK_SIZE, &_fakestack);
        _vm->addInstrumentedModuleFromAddr(funcPtr);

        printStartStatus(state);
        trace_code();
        trace_dynstr();
        trace_dynsym();
        trace_got();

        _vm->call(&_retVal, funcPtr);
        console->info("VM call end ret {:p}", _retVal);
        QBDI::alignedFree(_fakestack);
        _vm->clearAllCache();
    };

    static void vmCall(PTR soinfo, QBDI::rword funcPtr) {
        QBDI_TRACE(soinfo).vmCall(funcPtr);
    }

protected:
    static void handle_svc(SYSCALL svc_code, GPRState *gprState, bool simple = 1) {
#if defined(__aarch64__)
        // ssize_t svc_read(int fd, void *buf, size_t count)
        if (svc_code == SYSCALL::_NR_read) {
            loge("read(%p, %p, %d)\n", (void *)gprState->x0, (void *)gprState->x1, (int)gprState->x2);
            if (!simple)
                logd("%s", (const char *)gprState->x1);
        }

        // ssize_t svc_openat(int dirfd, const char* pathname, int flags)
        if (svc_code == SYSCALL::_NR_openat) {
            loge("openat(%d, %p [ '%s' ], %d [%s])\n", (int)gprState->x0, (void *)gprState->x1, (const char *)gprState->x1, (int)gprState->x2, magic_enum::enum_name((FileAccessFlag)gprState->x2).data());
        }

        // int mprotect(void* __addr, size_t __size, int __prot);
        if (svc_code == SYSCALL::_NR_mprotect) {
            int __prot = (int)gprState->x2;
            loge("mprotect(%p, %p, %d [ %s ])", (void *)gprState->x0, (void *)gprState->x1, __prot, getProtectionDetails(__prot).c_str());
        }

        // int close(int fd);
        if (svc_code == SYSCALL::_NR_close) {
            loge("close(%p)", (int)gprState->x0);
        }
#elif defined(__arm__)
        // TODO
#else
#error "Unsupported architecture"
#endif
    }
};

// BINDFUNC(qbdi) {
//     luabridge::getGlobalNamespace(L)
//         // .beginNamespace("qbdi")
//         // .addFunction("vmCall", luabridge::overload<PTR, QBDI::rword>(&QBDI_TRACE::vmCall))
//         // .endNamespace()
//         .beginClass<QBDI_TRACE>("qbdi_bind")
//         .addConstructor<void (*)()>()
//         .addConstructor<void (*)(PTR)>()
//         .addConstructor<void (*)(const soinfo *)>()
//         .addFunction("vmCall", luabridge::overload<QBDI::rword>(&QBDI_TRACE::vmCall))
//         .endClass();
//     static QBDI_TRACE trace;
//     luabridge::setGlobal(L, &trace, "qbdi");
// }