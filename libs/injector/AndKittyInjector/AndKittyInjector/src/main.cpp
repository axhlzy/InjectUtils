#include <thread>

#include <unistd.h>

#include <cstdint>
#include <string>

#include <sys/inotify.h>
#include <sys/types.h>

#include <chrono>
#define SLEEP_MICROS(x) { std::this_thread::sleep_for(std::chrono::microseconds(x)); }

#include "am_process_start.hpp"

#include <KittyUtils.hpp>

// parse cmd args
#include "KittyCmdln.hpp"

// injector
#include "Injector/KittyInjector.hpp"
KittyInjector kitInjector;

injected_info_t inject_lib                (int pid, const std::string &lib, bool use_memfd, bool hide_maps, bool hide_solist);
int             sync_watch_callback       (const std::string &path, uint32_t mask, std::function<bool(int wd, struct inotify_event* event)> cb);
int             am_process_start_callback (std::function<bool(const android_event_am_proc_start*)> cb);
void            watch_proc_inject         (const std::string& pkg, const std::string& lib, bool use_dl_memfd, bool hide_maps, bool hide_solist, unsigned int inj_delay, injected_info_t* ret);

bool bHelp = false;

static int inotifyFd = 0;

std::chrono::duration<double, std::milli> inj_ms {};

int main(int argc, char* args[])
{
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    setbuf(stdin, nullptr);

    KittyCmdln cmdline(argc, args);

    cmdline.setUsage("Usage: ./path/to/AndKittyInjector [-h] [-pkg] [-pid] [-lib] [ options ]");

    cmdline.addCmd("-h", "--help", "show available arguments", false, [&cmdline]() { KITTY_LOGI("\n%s", cmdline.toString().c_str()); bHelp = true; });

    char appPkg[0xff] = { 0 }; // required
    cmdline.addScanf("-pkg", "", "Target app package.", true, "%s", appPkg);

    int appPID = 0; // optional
    cmdline.addScanf("-pid", "", "Target app pid.", false, "%d", &appPID);

    char libPath[0xff] = { 0 }; // required
    cmdline.addScanf("-lib", "", "Library path to inject.", true, "%s", libPath);

    bool use_dl_memfd = false; // optional
    cmdline.addFlag("-dl_memfd", "", "Use memfd_create & dlopen_ext to inject library, useful to bypass path restrictions.", false, &use_dl_memfd);

    bool hide_maps = false; // optional
    cmdline.addFlag("-hide_maps", "", "Try to hide lib segments from /proc/[pid]/maps.", false, &hide_maps);
    
    bool hide_solist = false; // optional
    cmdline.addFlag("-hide_solist", "", "Try to remove lib from linker or NativeBridge solist.", false, &hide_solist);

    bool use_watch_app = false; // optional
    cmdline.addFlag("-watch", "", "Monitor process launch then inject, useful if you want to inject as fast as possible.", false, &use_watch_app);

    unsigned int inj_delay = 0; // optional
    cmdline.addScanf("-delay", "", "Set a delay in microseconds before injecting.", false, "%d", &inj_delay);

    cmdline.parseArgs();

    if (bHelp)
        return 0;

    if (!cmdline.requiredCmdsCheck())
    {
        KITTY_LOGE("Required arguments missing. see -h.");
        exit(1);
    }

    if (appPID > 0)
        KITTY_LOGI("Process ID: %d", appPID);

    KITTY_LOGI("Process Name: %s", appPkg);
    KITTY_LOGI("Library Path: %s", libPath);

    KITTY_LOGI("Use memfd dlopen: %d", use_dl_memfd ? 1 : 0);
    KITTY_LOGI("Hide lib from maps: %d", hide_maps ? 1 : 0);
    KITTY_LOGI("Hide lib from solist: %d", hide_solist ? 1 : 0);
    KITTY_LOGI("Use app watch: %d", use_watch_app ? 1 : 0);
    KITTY_LOGI("Inject delay: %d", inj_delay);

    injected_info_t injectedLibInfo = {};

    // process already alive and set
    if (appPID > 0)
    {
        if (inj_delay > 0)
            SLEEP_MICROS(inj_delay);

        injectedLibInfo = inject_lib(appPID, libPath, use_dl_memfd, hide_maps, hide_solist);
    }
    else if (use_watch_app)
    {
        if (KittyMemoryEx::getProcessID(appPkg) > 0) {
            KITTY_LOGE("-watch is used but the target process is already alive.");
            exit(1);
        }

        errno = 0;

        inotifyFd = inotify_init1(IN_CLOEXEC);
        if (inotifyFd < 0) {
            KITTY_LOGE("Failed to initialize inotify. last error = %s.", strerror(errno));
            exit(1);
        }

        KITTY_LOGI("Monitoring %s...", appPkg);

        watch_proc_inject(appPkg, libPath, use_dl_memfd, hide_maps, hide_solist, inj_delay, &injectedLibInfo);
    }
    // find pid and inject
    else
    {
        if (inj_delay > 0)
            SLEEP_MICROS(inj_delay);

        appPID = KittyMemoryEx::getProcessID(appPkg);
        if (appPID <= 0) {
            KITTY_LOGE("Couldn't find process id of %s.", appPkg);
            exit(1);
        }

        injectedLibInfo = inject_lib(appPID, libPath, use_dl_memfd, hide_maps, hide_solist);
    }

    if (!injectedLibInfo.is_valid())
    {
        KITTY_LOGE("Injection failed.");
        exit(1);
    }

    if (inj_ms.count() > 0)
        KITTY_LOGI("Injection took %f MS.", inj_ms.count());

    KITTY_LOGI("Injection succeeded.");
    return 0;
}

injected_info_t inject_lib(int pid, const std::string& lib, bool use_memfd, bool hide_maps, bool hide_solist)
{
    if (pid <= 0)
    {
        KITTY_LOGE("Invalid PID.");
        return {};
    }

    // ptrace attach will stop one thread in target process
    // use kill to stop the whole process instead

    bool stopped = kill(pid, SIGSTOP) != -1;
    if (stopped)
        KITTY_LOGI("inject_lib: Stopped target process threads.");
    else
        KITTY_LOGW("inject_lib: Failed to stop target process threads.");

    injected_info_t ret {};
    if (kitInjector.init(pid, EK_MEM_OP_IO))
    {
        KITTY_LOGI("inject_lib: Attaching to target process...");

        if (kitInjector.attach()) {
            KITTY_LOGI("inject_lib: Attached successfully.");
        } else {
            KITTY_LOGE("inject_lib: Failed to Attach.");
            return ret;
        }

        auto tm_start = std::chrono::high_resolution_clock::now();

        ret = kitInjector.injectLibrary(lib, RTLD_NOW | RTLD_LOCAL, use_memfd, hide_maps, hide_solist,
            [&pid, &stopped](injected_info_t& injected) {
                // callback called before calling injected lib EntryPoint
                // continue process so we can start thread safely in EntryPoint
                if (injected.is_valid() && stopped)
                {
                    KITTY_LOGI("inject_lib: Continuing target process...");
                    kill(pid, SIGCONT);
                    stopped = false;
                }
            });

        inj_ms = std::chrono::high_resolution_clock::now()-tm_start;

        kitInjector.detach();
    } else
        KITTY_LOGE("inject_lib: Couldn't initialize injector.");

    if (!ret.is_valid())
    {
        KITTY_LOGI("inject_lib: Killing target process...");
        kill(pid, SIGKILL);
    }

    return ret;
}

int sync_watch_callback(
    const std::string& path, uint32_t mask, std::function<bool(int wd, struct inotify_event* event)> cb)
{
    int wd = inotify_add_watch(inotifyFd, path.c_str(), mask);
    if (wd < 0)
        return -1;

    int ret = 0;

    char buffer[1024] = { 0 };
    for (;;) {
        memset(buffer, 0, sizeof(buffer));
        auto bytes = KT_EINTR_RETRY(read(inotifyFd, buffer, 1024));
        if (bytes < 0) {
            ret = -1;
            goto end;
        }

        int offset = 0;
        while (offset < bytes) {
            auto event = reinterpret_cast<inotify_event*>(&buffer[offset]);

            if (cb(wd, event)) {
                ret = 1;
                goto end;
            }

            offset += offsetof(inotify_event, name) + event->len;
        }
    }

    end:
    inotify_rm_watch(inotifyFd, wd);

    return ret;
}

// https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp
int am_process_start_callback(std::function<bool(const android_event_am_proc_start*)> cb)
{
    char log_tag[0xff] = {0};
    int log_tag_get = __system_property_get("persist.log.tag", log_tag);

    bool first = true;
    __system_property_set("persist.log.tag", "");

    auto logger_list = android_logger_list_alloc(0, 1, 0);

    errno = 0;
    auto* logger = android_logger_open(logger_list, LOG_ID_EVENTS);
    if (logger == nullptr)
        return false;

    bool ret = false;
    struct log_msg msg { };
    while (true)
    {
        if (android_logger_list_read(logger_list, &msg) <= 0) {
            ret = false;
            break;
        }

        if (first) {
            first = false;
            continue;
        }

        auto* event_header = reinterpret_cast<const android_event_header_t*>(&msg.buf[msg.entry.hdr_size]);

        if (event_header->tag != 30014)
            continue;

        if (cb(reinterpret_cast<const android_event_am_proc_start*>(event_header))) {
            ret = true;
            break;
        }
    }

    if (logger_list)
        android_logger_list_free(logger_list);

    if (log_tag_get > 0 && log_tag[0] != 0)
        __system_property_set("persist.log.tag", log_tag);

    return ret;
}

void watch_proc_inject(const std::string& pkg, const std::string& lib,
    bool use_dl_memfd, bool hide_maps, bool hide_solist, unsigned int inj_delay, injected_info_t* ret)
{    
    int pid = 0;
    int proc_monitor = am_process_start_callback([&](const android_event_am_proc_start* event) -> bool {
        if (int(pkg.length()) != event->process_name.length)
            return false;
        if (strncmp(event->process_name.data, pkg.c_str(), pkg.length()))
            return false;

        pid = event->pid.data;
        return true;
    });

    if (!proc_monitor) {
        KITTY_LOGE("watch_proc_inject: Failed to monitor process start. last error = %s.", strerror(errno));
        exit(1);
    } else if (pid <= 0) {
        KITTY_LOGE("watch_proc_inject: pid <= 0.");
        exit(1);
    }

    // inject on any event that isn't related to fd or timer
    auto proc_dir = KittyUtils::String::Fmt("/proc/%d", pid);
    int proc_dir_watch = sync_watch_callback(proc_dir, IN_ALL_EVENTS,
        [&](int, struct inotify_event* iev) -> bool {

            // skip fd event
            if (iev->len >= 2 && *(uint16_t*)iev->name == 0x6466)
                return false;

            // skip timerslack event
            if (iev->len >= 4 && *(uint32_t*)iev->name == 0x656d6974)
                return false;

            return true;
        });

    // maybe check cmdline if zygote or <preinitalized>
    // std::string cmdline;
    // KittyIOFile::readFileToString(KittyUtils::String::Fmt("/proc/%d/cmdline", pid), &cmdline);
    // KITTY_LOGI("cmdline %s", cmdline.c_str());

    if (proc_dir_watch <= 0) {
        KITTY_LOGE("watch_proc_inject: Failed to add watch on process directory. last error = %s.", strerror(errno));
        exit(1);
    }

    if (inj_delay > 0)
        SLEEP_MICROS(inj_delay);

    *ret = inject_lib(pid, lib, use_dl_memfd, hide_maps, hide_solist);
}